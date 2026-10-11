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
	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
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

func rootPersistentPreRunE(cmd *cobra.Command, _ []string) (err error) {
	if versionJSON {
		return nil
	}
	// Skip the full-daemon bootstrap (config load + audit store + PID
	// registration + telemetry) for lifecycle utilities that operate on
	// operator-supplied paths and do not touch DefenseClaw state. These
	// subcommands must run on hosts where the daemon has NOT been
	// installed yet (e.g. inside macOS uninstall.sh's --purge path,
	// which runs on hosts that may be halfway through a partial
	// install with no v8 config). Opting-in via the shared annotation
	// keeps the exemption discoverable in one place.
	if cmd != nil && cmd.Annotations["defenseclaw.skip-daemon-bootstrap"] == "true" {
		return nil
	}
	// The bare root command (it has no parent) is the per-user gateway
	// daemon. On a managed host it must refuse before any side effect:
	// before PID registration, before a per-user .env can set the
	// deployment pin, and before the config load and audit store open that
	// would create ~/.defenseclaw/audit.db.
	if cmd != nil && !cmd.HasParent() {
		// Stamp gateway.log before the config load and the audit store open
		// write to it, so their lines carry a time too (GAP-2109).
		startDaemonLogStamp()
		defer func() {
			if err != nil {
				stopDaemonLogStamp()
			}
		}()
		if err := refuseGatewayLifecycleOnManagedHost(); err != nil {
			return err
		}
		pinManagedUnixGatewayInputs(os.Stderr)
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
			if answer := managedWindowsConfigLoadError(cmd, err); answer != err {
				return answer
			}
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
	// Every command that resolves directory facts verifies an account of a
	// child AD domain only when the administrator lists it (GAP-1255).
	useridentity.SetTrustedADChildDomains(cfg.AIDiscovery.TrustedADChildDomains)
	if auditDir := filepath.Dir(cfg.AuditDB); auditDir != "." {
		if err := managed.PrepareServiceRuntimeDir(cfg.DeploymentMode, auditDir, "audit store directory"); err != nil {
			return fmt.Errorf("failed to prepare audit store directory: %w", err)
		}
	}
	if cmd != nil && !cmd.HasParent() {
		// The daemon owns the store: it moves a corrupt one aside and starts
		// on a new one instead of failing.
		auditStore, err = audit.OpenDaemonStore(cfg.AuditDB, os.Stderr, auditStoreOptions(cfg)...)
		if err != nil {
			return fmt.Errorf("failed to open audit store: %w", err)
		}
	} else {
		auditStore, err = openCommandAuditStore(cfg.AuditDB, auditStoreOptions(cfg)...)
		if err != nil {
			if cmd == nil || cmd.Annotations[auditOptionalAnnotation] != "true" {
				return err
			}
			// Connector teardown and verify never write audit events. A
			// damaged audit DB must not block restoring the agent's config
			// (uninstall aborted on it, GAP-1048).
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v; continuing without the audit store\n", err)
			auditStore = nil
		}
	}
	auditLog = nil
	if auditStore != nil {
		auditLog = audit.NewLogger(auditStore)
	}
	installCorrelator(auditStore, os.Stderr)
	if resolved := filepath.Join(cfg.DataDir, ".env"); resolved != filepath.Join(config.DefaultDataPath(), ".env") {
		loadDotEnvIntoOS(resolved)
	}
	return nil
}

// auditStoreOptions are the options every opener of cfg's audit.db passes:
// on a Secure Client host the store keeps main's schema (GAP-0246).
func auditStoreOptions(cfg *config.Config) []audit.StoreOption {
	if cfg != nil && cfg.SecureClientIntegration() {
		return []audit.StoreOption{audit.WithSecureClientSchema()}
	}
	return nil
}

// auditOptionalAnnotation marks a subcommand that writes no audit events, so
// an audit store that does not open is a warning instead of an error.
const auditOptionalAnnotation = "defenseclaw.audit-optional"

// openCommandAuditStore opens and initializes the audit store for a CLI
// subcommand (the daemon uses audit.OpenDaemonStore instead).
func openCommandAuditStore(path string, opts ...audit.StoreOption) (*audit.Store, error) {
	store, err := audit.NewStore(path, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit store: %w", err)
	}
	// A command's output is not the place for per-migration notes (GAP-0153).
	// Secure Client keeps them on stderr, as on main (issue #1092).
	if cfg == nil || !cfg.SecureClientIntegration() {
		store.SetMigrationProgress(io.Discard)
	}
	if err := store.Init(); err != nil {
		store.Close()
		return nil, fmt.Errorf("failed to init audit store: %w", err)
	}
	return store, nil
}

var rootCmd = &cobra.Command{
	Use:   "defenseclaw-gateway",
	Short: "DefenseClaw gateway sidecar daemon",
	Long: `DefenseClaw gateway sidecar - the per-user policy runtime. It answers the
hook calls of connected agents (Claude Code, Codex, Cursor, ...), runs the
guardrail proxy for LLM traffic, writes the audit log, and exposes the local
REST API used by the defenseclaw CLI and TUI. With OpenClaw configured it also
monitors the OpenClaw gateway WebSocket.

On a managed enterprise host it runs as a system service for every enrolled
account; administrators use 'defenseclaw-gateway enterprise linux|macos|windows'
(status, verify, repair, ...).

Run without arguments to start the sidecar daemon in the foreground; use
'defenseclaw-gateway start' to run it in the background.`,
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
		// Drain the gateway.log stamper before cobra prints an error.
		defer stopDaemonLogStamp()
		if versionJSON {
			return writeMachineVersion(cmd.OutOrStdout())
		}
		if err := refuseGatewayLifecycleOnManagedHost(); err != nil {
			return err
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
	// Skip the daemon bootstrap (PID registration + config load) for
	// lifecycle utilities that operate on operator-supplied paths and
	// do not touch DefenseClaw state. These subcommands must run on
	// hosts where the daemon has NOT been installed yet — most
	// importantly `enterprise hooks scrub` invoked from macOS
	// uninstall.sh's --purge path against a host with no v8
	// config.yaml. Mirrors the same exemption in
	// rootPersistentPreRunE above; the two initializers must agree on
	// the annotation contract or scrub regresses whenever it's routed
	// through the no-audit variant.
	if cmd != nil && cmd.Annotations["defenseclaw.skip-daemon-bootstrap"] == "true" {
		return nil
	}
	if err := daemon.RegisterCurrentProcess(); err != nil {
		return err
	}
	if err := loadGatewayCommandConfigFor(cmd); err != nil {
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
	return loadGatewayCommandConfigFor(nil)
}

// loadGatewayCommandConfigFor is loadGatewayCommandConfigOnly for cmd, so the
// managed Windows answer names the command the user ran.
func loadGatewayCommandConfigFor(cmd *cobra.Command) error {
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
		if answer := managedWindowsConfigLoadError(cmd, err); answer != err {
			return answer
		}
		return fmt.Errorf("failed to load config: %w", describeManagedConfigLoadError(err))
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
// never decodes an unconverted 0.8.x source; `defenseclaw migrate` converts a
// released config once, and this runtime refuses what it has not converted.
func loadGatewayConfigV8(path string) (*config.Config, *observabilityV8Startup, error) {
	// An un-migrated config_version 8 file runs as the v9 migration would
	// write it (read-only), so its data.json and audit.db policy still apply.
	// A failed migration refuses the file: run as raw v8 it would drop the
	// data.json admission policy and the audit.db block/allow entries.
	loaded, err := loadConfigV8Source(path, config.DefaultDataPath(), "", true)
	if err != nil {
		return nil, nil, err
	}
	candidate := loaded.runtime
	if !config.CurrentSchemaVersion(candidate.ConfigVersion) {
		return nil, nil, fmt.Errorf("the configuration is from an older DefenseClaw; run 'defenseclaw migrate' first")
	}
	// The managed-mode environment policy (envvars.Lookup) follows the
	// loaded config: on a standalone enterprise host ignore-listed variables
	// read as unset. Secure Client and per-user hosts read the raw env.
	envvars.SetManagedStandalone(candidate.StandaloneEnterprise())
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
	if c == nil || !config.CurrentSchemaVersion(c.ConfigVersion) {
		return nil, fmt.Errorf("the configuration is from an older DefenseClaw; run 'defenseclaw migrate' first")
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
	// A config reload reads credentials added to .env since the gateway started.
	config.RegisterDotEnvLoader(loadDotEnvIntoOS)
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
//
// Two error-carrier contracts converge here after the
// windows-enterprise-integration merge:
//
//   - *scrubExitError (main-branch, see enterprise_hooks_scrub.go)
//     ships a specific rc for `enterprise hooks scrub` (rc 2/3/4/5).
//   - *exitCodeError (integration-branch, see exit_code.go) ships a
//     specific rc for the withExitCode helper the Windows enterprise
//     lifecycle command uses (rc 1603 on preflight failures).
//
// exitCodeFor handles the scrub carrier; commandExitCode handles the
// integration carrier. Layered so exitCodeFor wins on ambiguity —
// scrub is the more specific subcommand.
func ExecuteContext(ctx context.Context) int {
	if ctx == nil {
		ctx = context.Background()
	}
	addManagedWindowsSetupAnswer(rootCmd)
	addManagedHostHelp(rootCmd)
	keepCommandTreeOfMainOnSecureClient(rootCmd)
	installUsageArgChecks(rootCmd)
	pendingUnknownSubcommand = nil
	err := rootCmd.ExecuteContext(ctx)
	if err == nil && pendingUnknownSubcommand != nil {
		err, pendingUnknownSubcommand = pendingUnknownSubcommand, nil
		rootCmd.PrintErrln(rootCmd.ErrPrefix(), err.Error())
	}
	if err == nil {
		return 0
	}
	// Cancellation is the expected completion path for an SCM stop. Do not
	// report it as a service failure or trigger failure-recovery restarts.
	if errors.Is(err, context.Canceled) {
		return 0
	}
	// scrubExitError check first (main-branch contract).
	if rc := exitCodeFor(err); rc != 1 {
		return rc
	}
	// integration-branch withExitCode helper.
	if rc := commandExitCode(err); rc != 1 {
		return rc
	}
	// An unknown top-level command is a usage error, as in the Python CLI
	// (GAP-1549).
	if isUnknownRootCommand(rootCmd, err) {
		return 2
	}
	return 1
}

// exitCodeFor is the pure error-to-int mapping for the scrub subcommand.
// Kept split so tests can drive it directly without spinning up the
// root Cobra command.
//
// Contract:
//
//   - err == nil                       -> rc 0
//   - err chain contains a
//     *scrubExitError                  -> that specific exit code
//   - anything else                    -> rc 1
//
// Matched against the CONCRETE type (*scrubExitError) rather than a
// generic `interface{ ExitCode() int }` on purpose. Go's stdlib
// exposes several unrelated error types that satisfy the same
// interface — most importantly *os/exec.ExitError (returned when a
// spawned subprocess exits non-zero). If a future RunE calls out to
// a helper binary and returns the resulting *exec.ExitError up the
// chain, an interface-based match would silently propagate that
// subprocess's exit code as OUR exit code (e.g. rc 127 = "command
// not found" from a broken PATH, rc 2 from unrelated tools) —
// meaningless in DefenseClaw's contract and prone to colliding with
// our own well-defined codes (uninstall.sh: rc 2 = missing file, rc
// 3 = unknown connector, rc 4 = parse failure). Anchoring on the
// concrete type keeps the contract auditable: exit-code propagation
// requires an explicit scrubExitError construction, never a
// coincidental interface satisfaction.
//
// errors.As still walks the wrap chain so
// `fmt.Errorf("context: %w", scrubExitErr)` continues to propagate
// correctly — the concrete-type constraint only affects what
// counts as a "carrier".
func exitCodeFor(err error) int {
	if err == nil {
		return 0
	}
	var ec *scrubExitError
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return 1
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
	managedHost := envvars.ManagedStandalone() || dotEnvManagedSource()
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
		// A managed standalone host skips what the registry ignores there.
		if managedHost && envvars.ManagedPolicy(k) == envvars.ManagedIgnore {
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

// dotEnvManagedSource reports whether the active config.yaml describes a
// managed standalone host, for .env loading that runs before the config is
// loaded.
func dotEnvManagedSource() bool {
	raw, err := safefile.ReadRegularFileBounded(config.ConfigPath(), int64(config.ObservabilityV8MaxSourceBytes))
	return err == nil && config.StandaloneManagedSource(raw)
}

func dotEnvKeyIsProcessControl(key string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(key))
	switch normalized {
	case "ALL_PROXY", "BASH_ENV", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "COMSPEC",
		"CURL_CA_BUNDLE",
		"DEFENSECLAW_CODEX_LOOPBACK_TRUST",
		"DEFENSECLAW_CONFIG", "DEFENSECLAW_DATA_DIR", "DEFENSECLAW_GATEWAY_BIN",
		// The deployment mode and profile pins come only from the service
		// definition; a writable .env must not make an unmanaged host
		// invalid or move a service onto another mode or profile.
		managed.DeploymentModeEnv, managed.EnterpriseProfileEnv,
		"DEFENSECLAW_HOME", "DEFENSECLAW_DEV", "DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM",
		"DEFENSE" + "CLAW_DISABLE_REDACTION", "DEFENSECLAW_DUMP_RAW_SECRETS",
		"DEFENSECLAW_FAIL_MODE", "DEFENSECLAW_FORCE_AWS_HTTP1_SHIM",
		"DEFENSECLAW_JSONL_DISABLE",
		"DEFENSECLAW_OTEL_TLS_INSECURE", "DEFENSECLAW_POLICY_VALIDATE_ALLOW_NO_OPA",
		"DEFENSECLAW_REVEAL_PII",
		"DEFENSECLAW_SANDBOX_ID", "DEFENSECLAW_SANDBOX_NAME", "DEFENSECLAW_SANDBOX_TOKEN",
		"DEFENSECLAW_STRICT_AVAILABILITY",
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
