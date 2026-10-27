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
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// connectorCmd is the parent for low-level connector lifecycle subcommands
// exposed via the gateway binary. These commands intentionally bypass the
// interactive `defenseclaw setup` flow and operate directly on a single
// connector implementation. They exist so that operators (and the Python
// `defenseclaw uninstall` flow) have a deterministic way to:
//
//   - Tear down the configuration patches that a connector applied
//     (`teardown`).
//   - Verify that no DefenseClaw residue remains in the agent framework's
//     config (`verify`).
//   - Inspect which pristine backups the gateway has on disk so that they
//     can be restored or rotated out (`list-backups`).
var connectorCmd = &cobra.Command{
	Use:   "connector",
	Short: "Inspect and manage individual connector lifecycle state",
	Long: `Low-level connector lifecycle commands.

These subcommands work on one connector (for example claudecode, codex,
cursor or opencode) and bypass the interactive 'defenseclaw setup' flow.
'defenseclaw uninstall' uses them, and they help clean up state that a
connector switch left behind.

Each subcommand accepts --connector. When omitted, it uses the active
connector: the one the gateway last started, else guardrail.connector in
config.yaml. 'defenseclaw guardrail status' lists the connector names.
`,
}

var (
	connectorFlagName                 string
	connectorFlagJSON                 bool
	connectorFlagDataDir              string
	connectorFlagConfigHome           string
	connectorFlagHookExe              string
	connectorRollbackRestore          bool
	connectorVerifySetupParent        string
	connectorVerifySetupStartIdentity string
	connectorVerifyCleanupRecord      string
	connectorVerifyCleanupTransaction string
)

// connectorExit is the indirection used in place of os.Exit so tests can
// observe the exit code without terminating the test binary. Production
// code paths leave this at the default (real os.Exit).
var connectorExit = os.Exit

// connectorReconcileEvery is reconcile --every-connector.
var connectorReconcileEvery bool

// connectorReconcileReadBack reads a reconciled registration back; tests
// replace it to stand for a hook that does not answer.
var connectorReconcileReadBack = connector.OwnedHooksPresent
var connectorHookRuntimePaths = hookruntime.CurrentUserPaths
var connectorSaveOpenCodeActive = connector.SaveActiveConnectors
var connectorSaveOpenCodeLock = connector.SaveFreshHookContractLockEntry
var connectorSaveAmpLock = connector.SaveFreshHookContractLockEntry
var connectorEnsureHookAPIToken = connector.EnsureHookAPIToken
var connectorVerifyRootPersistentPreRun = rootPersistentPreRunE
var connectorCheckPlatformSupportOnHost = connector.CheckPlatformSupportOnHost

var connectorTeardownCmd = &cobra.Command{
	Use:   "teardown",
	Short: "Run the active connector's Teardown (remove its config patches)",
	Long: `Tear down the named connector.

Calls Connector.Teardown(opts) which is responsible for:
  - Restoring the agent framework's config from its pristine backup.
  - Removing any hook scripts the connector wrote into ~/.defenseclaw.
  - Clearing any environment shims the connector installed.

This subcommand does NOT touch the sidecar's own systemd unit, the
gateway token, or the audit DB. It is the idempotent inverse of
Connector.Setup() for a single connector. It marks that connector inactive in
the runtime state before removing files so a still-running hook guard cannot
immediately reinstall the configuration being deliberately torn down.`,
	Annotations: map[string]string{auditOptionalAnnotation: "true"},
	RunE:        runConnectorTeardown,
}

var connectorPrepareRollbackCmd = &cobra.Command{
	Use:   "prepare-rollback",
	Short: "Rewrite hook entries in the form an earlier release removes (run by the installers)",
	Long: `Rewrite the hook entries this release writes in a shape an earlier release
does not recognise into the shape it does, so that release's uninstall still
removes them after a rollback (GAP-1284). The installers run it before
'defenseclaw rollback' restores the previous install. Without --connector it
covers every connector that has such entries. Setup writes the current form
again when you roll forward.`,
	Hidden:      true,
	Annotations: map[string]string{auditOptionalAnnotation: "true"},
	RunE:        runConnectorPrepareRollback,
}

var connectorPruneOrphansCmd = &cobra.Command{
	Use:   "prune-orphans",
	Short: "Remove the DefenseClaw hook entries of connectors that are not configured (run by the installers)",
	Long: `Tear down every connector that neither config.yaml nor the runtime
connector state names but whose agent config still holds DefenseClaw hook
entries for this data directory. A rollback restored a data directory from
before such a connector was set up, so the agent ran a hook script that no
longer existed and Claude Code blocked every prompt (GAP-0009). Only the
DefenseClaw-owned entries go, as with 'connector teardown'. With --connector
only that connector is checked. The installers run it after a rollback or an
upgrade, and 'defenseclaw setup remove' runs it for a connector that is not
configured.`,
	Hidden:      true,
	Annotations: map[string]string{auditOptionalAnnotation: "true"},
	RunE:        runConnectorPruneOrphans,
}

var connectorVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify that the connector left no residual state behind",
	Long: `Run Connector.VerifyClean() for the named connector.

VerifyClean returns nil when the agent framework's configuration is free
of DefenseClaw artifacts (hooks, env files, config patches, shims) and
returns a descriptive error listing residual artifacts otherwise. This is
the same check the sidecar runs before swapping connectors, so it is the
canonical way to answer "did teardown actually work?".

Exit codes:
  0   connector is clean
  1   connector has residual state (details printed to stderr)
  2   connector unknown / config error`,
	Annotations:       map[string]string{auditOptionalAnnotation: "true"},
	PersistentPreRunE: runConnectorVerifyPersistentPreRunE,
	RunE:              runConnectorVerify,
}

var connectorReconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "Refresh one connector's installed runtime registration",
	Long: `Reconcile the named connector from the current DefenseClaw config.

This is the selected-connector setup primitive used by transactional policy
mutations. It does not restart the gateway and does not setup peer connectors.

With --every-connector (run by the installers after an upgrade or repair of a
gateway that is not running) it refreshes every connector the config guards,
as the gateway's start does, and reads each registration back. It exits 3 and
names each connector that is not on its current hook, with the cause.`,
	RunE: runConnectorReconcile,
}

var connectorCheckAgentSettingsCmd = &cobra.Command{
	Use:   "check-agent-settings",
	Short: "Check that the agent's own settings let DefenseClaw hooks run (run by setup)",
	Long: `Run the check the named connector's Setup starts with: the agent's own
settings must not turn its hooks off or fail to parse (for example a Codex
config.toml with a syntax error, or Claude Code disableAllHooks), and the
data directory's shared hook config (hooks/.hookcfg) must be one the hooks
read (GAP-1325). It changes nothing. 'defenseclaw setup' runs it before it restarts the gateway, so such
settings stop setup with the reason while the running gateway keeps enforcing
(GAP-0615).

Exit codes:
  0   the settings let the hooks run
  1   the settings refuse the hooks (the reason names the file and the fix)
  2   connector unknown / config error`,
	Hidden:      true,
	Annotations: map[string]string{auditOptionalAnnotation: "true"},
	RunE:        runConnectorCheckAgentSettings,
}

var connectorListBackupsCmd = &cobra.Command{
	Use:   "list-backups",
	Short: "List pristine connector backups stored under the data directory",
	Long: `Inspect the data directory and list every connector pristine backup
that the gateway has written.

These backups are created by Connector.Setup() before the gateway patches
the agent framework's config. They are the rollback point that
'connector teardown' uses, so listing them is the safest way to check
whether 'defenseclaw uninstall' will be able to restore the user's
original configuration. Both legacy flat backups and managed backups
under connector_backups/<connector>/ are shown.

The default output is a human-readable table:

  CONNECTOR    PATH                                              SIZE
  codex        /home/u/.defenseclaw/codex_backup.json            1234

Pass --json for a structured payload suitable for piping into 'jq'.`,
	RunE: runConnectorListBackups,
}

func init() {
	connectorCheckAgentSettingsCmd.Flags().String("workspace-dir", "",
		"Check settings in this requested workspace (empty means global user scope)")
	_ = connectorCheckAgentSettingsCmd.Flags().MarkHidden("workspace-dir")
	connectorPrepareRollbackCmd.Flags().BoolVar(&connectorRollbackRestore, "restore", false,
		"Restore authenticated current-release hooks after an aborted rollback")
	connectorCmd.PersistentFlags().StringVar(&connectorFlagName, "connector", "",
		"Connector name (default: the active connector; 'defenseclaw guardrail status' lists them)")
	connectorCmd.PersistentFlags().BoolVar(&connectorFlagJSON, "json", false,
		"Emit machine-readable JSON instead of the human-readable view")
	connectorCmd.PersistentFlags().StringVar(&connectorFlagDataDir, "data-dir", "",
		"Use this DefenseClaw data directory (default: data_dir in config.yaml, usually ~/.defenseclaw)")
	connectorCmd.PersistentFlags().StringVar(&connectorFlagConfigHome, "config-home", "",
		"Bind native connector maintenance to an installer-validated configuration home")
	_ = connectorCmd.PersistentFlags().MarkHidden("config-home")
	connectorCmd.PersistentFlags().StringVar(&connectorFlagHookExe, "hook-executable", "",
		"Bind native connector maintenance to an installer-validated hook launcher")
	_ = connectorCmd.PersistentFlags().MarkHidden("hook-executable")
	connectorVerifyCmd.Flags().StringVar(
		&connectorVerifySetupParent,
		"internal-setup-parent",
		"",
		"internal authenticated Setup parent binding",
	)
	_ = connectorVerifyCmd.Flags().MarkHidden("internal-setup-parent")
	connectorVerifyCmd.Flags().StringVar(
		&connectorVerifySetupStartIdentity,
		"internal-setup-start-identity",
		"",
		"internal authenticated Setup process-instance binding",
	)
	_ = connectorVerifyCmd.Flags().MarkHidden("internal-setup-start-identity")
	connectorVerifyCmd.Flags().StringVar(
		&connectorVerifyCleanupRecord,
		"internal-deferred-cleanup-record",
		"",
		"internal authenticated deferred-cleanup record binding",
	)
	_ = connectorVerifyCmd.Flags().MarkHidden("internal-deferred-cleanup-record")
	connectorVerifyCmd.Flags().StringVar(
		&connectorVerifyCleanupTransaction,
		"internal-deferred-cleanup-transaction",
		"",
		"internal authenticated deferred-cleanup transaction binding",
	)
	_ = connectorVerifyCmd.Flags().MarkHidden("internal-deferred-cleanup-transaction")

	connectorReconcileCmd.Flags().BoolVar(&connectorReconcileEvery, "every-connector", false,
		"refresh and read back every connector the config guards; exit 3 naming each that is not on its current hook")
	_ = connectorReconcileCmd.Flags().MarkHidden("every-connector")

	connectorCmd.AddCommand(connectorTeardownCmd)
	connectorCmd.AddCommand(connectorPrepareRollbackCmd)
	connectorCmd.AddCommand(connectorPruneOrphansCmd)
	connectorCmd.AddCommand(connectorVerifyCmd)
	connectorCmd.AddCommand(connectorReconcileCmd)
	connectorCmd.AddCommand(connectorCheckAgentSettingsCmd)
	connectorCmd.AddCommand(connectorListBackupsCmd)

	rootCmd.AddCommand(connectorCmd)
}

func runConnectorVerifyPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if connectorVerifySetupParent == "" &&
		connectorVerifySetupStartIdentity == "" &&
		connectorVerifyCleanupRecord == "" &&
		connectorVerifyCleanupTransaction == "" {
		return connectorVerifyRootPersistentPreRun(cmd, args)
	}
	if err := validateDeferredUninstallConnectorVerify(cmd); err != nil {
		return fmt.Errorf("connector verify deferred-uninstall authorization: %w", err)
	}
	// The authenticated deferred-uninstall child is deliberately configless:
	// DELETEUSERDATA has already removed the runtime v8 source. VerifyClean uses
	// only the transaction-bound data/config homes validated above.
	cfg = nil
	activeObservabilityV8Startup = nil
	version.SetBinaryVersion(appVersion)
	return nil
}

// resolveActiveConnectorName returns the connector name to operate on for
// teardown/verify, honouring --connector first, then the on-disk active
// connector marker, then guardrail.connector, then claw.mode, then "openclaw".
func resolveActiveConnectorName(dataDir string) string {
	if name := strings.TrimSpace(connectorFlagName); name != "" {
		return strings.ToLower(name)
	}
	if dataDir != "" {
		if name := strings.TrimSpace(connector.LoadActiveConnector(dataDir)); name != "" {
			return strings.ToLower(name)
		}
	}
	if cfg != nil {
		if name := strings.TrimSpace(cfg.Guardrail.Connector); name != "" {
			return strings.ToLower(name)
		}
		if mode := strings.TrimSpace(string(cfg.Claw.Mode)); mode != "" {
			return strings.ToLower(mode)
		}
	}
	return "openclaw"
}

// resolveConnectorDataDir returns the data directory to inspect.
// Honours --data-dir first, then cfg.DataDir, then the package default.
// The data directory is treated as a path that the gateway already trusts
// (it is provided by the operator via flag/config and is not derived from
// untrusted user input crossing a trust boundary).
func resolveConnectorDataDir() string {
	if d := strings.TrimSpace(connectorFlagDataDir); d != "" {
		return d
	}
	if cfg != nil && cfg.DataDir != "" {
		return cfg.DataDir
	}
	return ""
}

// bindConnectorLifecycleConfigHome turns Setup's explicit, validated home
// binding into the connector's existing environment contract. Normal operator
// calls remain unchanged when the hidden flag is absent. Setup supplies both
// the flag and a matching environment value so teardown and VerifyClean cannot
// silently agree on an unrelated inherited profile.
func bindConnectorLifecycleConfigHome(connectorName string) (func(), error) {
	home := connectorFlagConfigHome
	if home == "" {
		if err := validateConnectorLifecycleHookExecutable(connectorName, home); err != nil {
			return nil, err
		}
		return func() {}, nil
	}
	if strings.TrimSpace(home) != home || strings.ContainsAny(home, "\x00\r\n") ||
		!filepath.IsAbs(home) || filepath.Clean(home) != home {
		return nil, fmt.Errorf("config home is not an absolute normalized path")
	}
	if err := validateConnectorLifecycleConfigHomePath(home); err != nil {
		return nil, fmt.Errorf("config home path is unsafe: %w", err)
	}
	if err := validateConnectorLifecycleHookExecutable(connectorName, home); err != nil {
		return nil, err
	}

	variable := ""
	switch connectorName {
	case "codex":
		variable = "CODEX_HOME"
	case "claudecode":
		variable = "CLAUDE_CONFIG_DIR"
	case "amp":
		// Amp has no config-home environment override. SetupOpts.ConfigHome
		// carries the validated lifecycle path without mutating USERPROFILE.
		return func() {}, nil
	case "copilot":
		variable = "COPILOT_HOME"
	case "cursor":
		// Cursor has no documented configuration-home environment variable.
		// The hidden maintenance flag is carried through SetupOpts.ConfigHome
		// instead of inventing an upstream-facing override.
		return func() {}, nil
	case "devin":
		// Devin has no supported config-home environment override. The
		// authenticated installer binding flows through SetupOpts.ConfigHome.
		return func() {}, nil
	case legacyconnector.RetiredDesktopID:
		// Retired-ID cleanup has no vendor home override variable. Bind
		// DefenseClaw's connector path resolver directly to Setup's validated
		// profile root; never inherit a maintenance process's ambient
		// USERPROFILE.
		return connector.BindUserHomeDir(home)
	case "antigravity":
		// Google has no documented Antigravity configuration-home environment
		// variable. The hidden maintenance flag already flows through
		// SetupOpts.ConfigHome, so do not invent or export a vendor override.
		return func() {}, nil
	case "opencode":
		variable = "OPENCODE_CONFIG_DIR"
	case "hermes":
		variable = "HERMES_HOME"
	case "openhands", "omnigent":
		// until 1.1: the teardown-only cleanup of OpenHands and OmniGent
		// reads the home native Setup bound from SetupOpts.ConfigHome.
		return func() {}, nil
	default:
		return nil, fmt.Errorf("explicit config home is unsupported for connector %q", connectorName)
	}
	if strings.TrimSpace(home) != home || strings.ContainsAny(home, "\x00\r\n") ||
		!filepath.IsAbs(home) || filepath.Clean(home) != home {
		return nil, fmt.Errorf("config home is not an absolute normalized path")
	}
	if err := validateConnectorLifecycleConfigHomePath(home); err != nil {
		return nil, fmt.Errorf("config home path is unsafe: %w", err)
	}
	if connectorName == "amp" {
		return func() {}, nil
	}
	previous, existed := os.LookupEnv(variable)
	if err := os.Setenv(variable, home); err != nil {
		return nil, fmt.Errorf("bind %s: %w", variable, err)
	}
	return func() {
		if existed {
			_ = os.Setenv(variable, previous)
		} else {
			_ = os.Unsetenv(variable)
		}
	}, nil
}

func validateConnectorLifecycleHookExecutable(connectorName, configHome string) error {
	executable := connectorFlagHookExe
	if executable == "" {
		if connectorName == "hermes" && configHome != "" {
			return fmt.Errorf("Hermes maintenance hook executable is empty")
		}
		return nil
	}
	if connectorName != "hermes" {
		return fmt.Errorf("explicit hook executable is unsupported for connector %q", connectorName)
	}
	if configHome == "" {
		return fmt.Errorf("explicit Hermes hook executable requires an installer-bound config home")
	}
	if strings.TrimSpace(executable) != executable ||
		strings.ContainsAny(executable, "\"\x00\r\n") ||
		!filepath.IsAbs(executable) ||
		filepath.Clean(executable) != executable ||
		!strings.EqualFold(filepath.Base(executable), "defenseclaw-hook.exe") {
		return fmt.Errorf("Hermes maintenance hook executable is not an absolute normalized DefenseClaw launcher path")
	}
	paths, err := connectorHookRuntimePaths()
	if err != nil {
		return fmt.Errorf("resolve canonical Hermes hook executable: %w", err)
	}
	canonical := strings.TrimSpace(paths.Launcher)
	if canonical == "" || executable != canonical {
		return fmt.Errorf("Hermes maintenance hook executable is not the exact canonical stable HookRuntime launcher")
	}
	return nil
}

// newConnectorRegistryWithPlugins mirrors the sidecar startup path
// (NewGuardrailProxy / APIServer.Run) by registering both the
// built-in connectors AND any plugin connectors discovered under the
// configured plugin directory. ("Connector lifecycle
// commands cannot operate on plugin connectors"): without this, a
// plugin connector named in active_connector.json or via --connector
// is reported as unknown by `connector teardown` and `connector
// verify`, leaving plugin-owned hooks and config patches behind on
// uninstall.
//
// Plugin discovery failures are logged and tolerated: built-in
// connectors should still resolve so an unrelated plugin error never
// blocks `teardown openclaw` etc.
func newConnectorRegistryWithPlugins() *connector.Registry {
	reg := connector.NewDefaultRegistry()
	if cfg == nil {
		return reg
	}
	pluginDir := strings.TrimSpace(cfg.PluginDir)
	if pluginDir == "" {
		return reg
	}
	if err := reg.DiscoverPlugins(pluginDir); err != nil {
		fmt.Fprintf(os.Stderr,
			"connector cli: plugin discovery in %q failed: %v\n",
			pluginDir, err)
	}
	return reg
}

// resolveConnectorOpts builds the SetupOpts used by Teardown/VerifyClean.
// APIToken / ProxyAddr / APIAddr are filled in best-effort from cfg —
// teardown does not need them, but VerifyClean for some connectors checks
// that env files no longer reference the proxy address, so populating
// them mirrors what the sidecar would pass at boot.
func resolveConnectorOpts(dataDir string) connector.SetupOpts {
	return resolveConnectorOptsFor(dataDir, resolveActiveConnectorName(dataDir))
}

// resolveConnectorOptsFor is resolveConnectorOpts for the named connector.
func resolveConnectorOptsFor(dataDir, name string) connector.SetupOpts {
	opts := connector.SetupOpts{
		DataDir:        dataDir,
		ConfigHome:     connectorFlagConfigHome,
		HookExecutable: connectorFlagHookExe,
		Interactive:    false,
	}
	if name == "amp" {
		opts.ConfigHome = strings.TrimSpace(connectorFlagConfigHome)
	}
	if cfg == nil {
		return opts
	}
	// Bind addresses are best-effort: VerifyClean only uses them as
	// substring needles for residue detection.
	if cfg.Gateway.APIPort != 0 {
		opts.APIAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Gateway.APIPort)
	}
	if cfg.Guardrail.Port != 0 {
		opts.ProxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Guardrail.Port)
	}
	opts.WorkspaceDir = cfg.ConnectorWorkspaceDir()
	// Setup writes this into Codex's [otel] table; a surgical teardown only
	// removes it when it knows the same value (GAP-1979).
	opts.CodexOtelEnvironment = cfg.Environment
	opts.AgentExecutable = connector.LoadCachedAgentExecutable(dataDir, name)
	opts.APIToken = cfg.Gateway.ResolvedToken()
	return opts
}

// reconcileSupportedConnectors are the connectors whose selected refresh
// native Setup runs; any other connector is refused before it changes
// anything.
var reconcileSupportedConnectors = []string{
	"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "opencode",
}

func reconcileSupportedConnector(name string) bool {
	return slices.Contains(reconcileSupportedConnectors, name)
}

func runConnectorCheckAgentSettings(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "connector check-agent-settings: no data directory configured (set --data-dir or run 'defenseclaw init')")
		connectorExit(2)
		return nil
	}
	name := resolveActiveConnectorName(dataDir)
	if name == "codex" && connectorFlagConfigHome == "" {
		defer connector.PinConnectorConfigRootsForCommand(dataDir)()
	}
	restoreConfigHome, err := bindConnectorLifecycleConfigHome(name)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "connector check-agent-settings: %v\n", err)
		connectorExit(2)
		return nil
	}
	defer restoreConfigHome()
	conn, ok := newConnectorRegistryWithPlugins().Get(name)
	if !ok {
		fmt.Fprintf(cmd.ErrOrStderr(), "connector check-agent-settings: unknown connector %q\n", name)
		connectorExit(2)
		return nil
	}
	opts := resolveConnectorOptsFor(dataDir, name)
	if cmd.Flags().Changed("workspace-dir") {
		workspace, err := cmd.Flags().GetString("workspace-dir")
		if err != nil || (workspace != "" && (!filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace)) {
			fmt.Fprintln(cmd.ErrOrStderr(), "connector check-agent-settings: workspace must be empty or an absolute normalized path")
			connectorExit(2)
			return nil
		}
		opts.WorkspaceDir = workspace
	}
	if cfg != nil {
		opts.ManagedEnterprise = managed.IsManagedEnterprise(cfg.DeploymentMode)
	}
	// Every connector of the data directory shares hooks/.hookcfg, so a
	// malformed one refuses the setup of any of them (GAP-1325).
	refusal := connector.SharedHookSidecarRefusal(opts)
	if refusal == nil {
		refusal = connector.CheckAgentSettings(conn, opts)
	}
	if connectorFlagJSON {
		payload := map[string]any{"connector": name, "action": "check-agent-settings", "refused": refusal != nil}
		if refusal != nil {
			payload["reason"] = refusal.Error()
		}
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
	} else if refusal != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "connector %s: %v\n", name, refusal)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "connector %s: the agent's settings let DefenseClaw hooks run\n", name)
	}
	if refusal != nil {
		connectorExit(1)
	}
	return nil
}

func runConnectorReconcile(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector reconcile: no data directory configured")
	}
	if connectorReconcileEvery {
		return runConnectorReconcileEvery(cmd, dataDir)
	}
	name := resolveActiveConnectorName(dataDir)
	return reconcileConnectorRuntime(cmd, dataDir, name, false, func(_ connector.Connector, opts connector.SetupOpts) error {
		if connectorFlagJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
				"connector": name,
				"action":    "reconcile",
				"ok":        true,
				"fail_mode": opts.HookFailMode,
			})
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  %s %s runtime reconciled\n", Style(glyph("✓", "OK"), "fg=green", "bold"), name)
		return nil
	})
}

// runConnectorReconcileEvery is reconcile --every-connector. An upgrade or
// repair of a gateway that is not running does not start it, so nothing
// rendered this release's hooks: a Hermes hook an earlier release wrote
// cannot answer this release's execution probe, and the install exited 0
// with Hermes unprotected. This refreshes every connector the config guards,
// as the gateway's boot does (Setup for each one, not only the connectors a
// selected policy refresh supports), and reads each registration back. Exit 3
// names each connector that is not on its current hook, with the cause.
func runConnectorReconcileEvery(cmd *cobra.Command, dataDir string) error {
	if strings.TrimSpace(connectorFlagName) != "" || connectorFlagJSON {
		return errors.New("connector reconcile: --every-connector takes neither --connector nor --json")
	}
	var causes []string
	for _, name := range guardedConnectorNames(cfg) {
		if err := reconcileOrReadBackConnector(cmd, dataDir, name); err != nil {
			causes = append(causes, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(causes) == 0 {
		return nil
	}
	return withExitCode(fmt.Errorf("not every connector is on its current hook: %s", strings.Join(causes, "; ")),
		gatewayStartAdmissionRefusedExitCode)
}

func reconcileOrReadBackConnector(cmd *cobra.Command, dataDir, name string) error {
	readBack := func(conn connector.Connector, opts connector.SetupOpts) error {
		present, err := connectorReconcileReadBack(conn, opts)
		if err != nil {
			return fmt.Errorf("its hook registration could not be read back: %w", err)
		}
		if !present {
			if reason := strings.TrimSpace(connector.OwnedHooksAbsentReason(conn, opts)); reason != "" {
				return fmt.Errorf("its current hook is not in place: %s", reason)
			}
			return errors.New("its current hook is not in place; start the gateway (defenseclaw-gateway start), then check: defenseclaw doctor")
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  %s %s is on its current hook\n", Style(glyph("✓", "OK"), "fg=green", "bold"), name)
		return nil
	}
	// A Kiro, OpenClaw, ZeptoClaw or plugin connector kept the hook an
	// earlier release rendered, and a read-back of its registration passed
	// with it: refresh every connector, as the gateway's start does.
	if _, ok := newConnectorRegistryWithPlugins().Get(name); !ok {
		return errors.New("this DefenseClaw build does not ship it")
	}
	return reconcileConnectorRuntime(cmd, dataDir, name, true, readBack)
}

// reconcileConnectorOpts is the Setup input reconcile renders name with.
func reconcileConnectorOpts(dataDir, name string) connector.SetupOpts {
	opts := resolveConnectorOptsFor(dataDir, name)
	if cfg != nil {
		opts.CodexOtelEnvironment = cfg.Environment
		opts.HookFailMode = cfg.EffectiveHookOutageFailModeForConnector(name)
		opts.SecureClientHookDelivery = cfg.SecureClientIntegration()
		opts.GuardrailMode = cfg.EffectiveGuardrailModeForConnector(name)
		opts.HILTEnabled = cfg.EffectiveHILTForConnector(name).Enabled
		opts.ManagedEnterprise = managed.IsManagedEnterprise(cfg.DeploymentMode)
	}
	opts.AgentVersion = connector.LoadCachedAgentVersion(dataDir, name)
	opts.AgentExecutable = connector.LoadCachedAgentExecutable(dataDir, name)
	return opts
}

// reconcileConnectorRuntime refreshes name's runtime registration and calls
// done with the connector and the options it rendered, while the config
// home binding is still in place. A selected policy refresh (every false)
// takes only reconcileSupportedConnectors; --every-connector takes any
// connector this build or its plugins ship.
func reconcileConnectorRuntime(
	cmd *cobra.Command,
	dataDir, name string,
	every bool,
	done func(connector.Connector, connector.SetupOpts) error,
) error {
	// A command run outside cobra (tests, --every-connector helpers) has no
	// context; Codex policy inspection derives a timeout from it (GAP-1282).
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if name == "codex" && connectorFlagConfigHome == "" {
		defer connector.PinConnectorConfigRootsForCommand(dataDir)()
	}
	restoreConfigHome, err := bindConnectorLifecycleConfigHome(name)
	if err != nil {
		return fmt.Errorf("connector reconcile: %w", err)
	}
	defer restoreConfigHome()
	reg := newConnectorRegistryWithPlugins()
	conn, ok := reg.Get(name)
	if !ok {
		return fmt.Errorf("connector reconcile: unknown connector %q", name)
	}
	if !every && !reconcileSupportedConnector(name) {
		return fmt.Errorf("connector reconcile: selected refresh is supported only for %s", strings.Join(reconcileSupportedConnectors, ", "))
	}
	if warning, supportErr := connector.CheckPlatformSupportOnHost(name); supportErr != nil {
		return fmt.Errorf("connector reconcile %s: %w", name, supportErr)
	} else if warning != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "connector reconcile %s: warning: %s\n", name, warning)
	}
	opts := reconcileConnectorOpts(dataDir, name)
	previous := connector.LoadHookContractLockEntry(dataDir, name)
	if opts.AgentVersion == "" {
		// A scoped policy refresh must not downgrade a previously verified
		// registration merely because discovery cache cleanup ran between
		// setups. Reuse the lock's exact observed version as audit evidence.
		opts.AgentVersion = previous.RawAgentVersion
	}
	resolution := connector.ResolveHookContract(name, opts.AgentVersion)
	opts.HookContractID = resolution.Contract.ContractID
	actionMode := cfg != nil && strings.EqualFold(
		strings.TrimSpace(cfg.EffectiveGuardrailModeForConnector(name)), "action",
	)
	if connector.HookContractNeedsActionOverride(resolution) && actionMode &&
		envvars.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") != "1" {
		return fmt.Errorf(
			"connector reconcile %s: agent version %q is not verified against a known hook contract: %s",
			name, opts.AgentVersion, resolution.Reason,
		)
	}
	if previous.Connector != "" {
		current := connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
		// A contract that only a different DefenseClaw release changed for the
		// same agent version, or an agent update that still resolves to a
		// contract, is refreshed by the Setup below, as at gateway boot.
		if connector.HookContractCompatibilityDrifted(previous, current) && actionMode &&
			envvars.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") != "1" &&
			!connector.HookContractChangedByDefenseClawRelease(previous, current) &&
			!connector.HookContractAgentUpdateAdmitted(previous, current) {
			return fmt.Errorf("connector reconcile %s: hook contract compatibility drift", name)
		}
	}
	hookToken, err := connector.LoadHookAPIToken(dataDir, name)
	if err != nil {
		return fmt.Errorf("connector reconcile: load scoped hook token: %w", err)
	}
	tokenCreated := false
	if hookToken == "" {
		hookToken, err = connectorEnsureHookAPIToken(dataDir, name)
		if err != nil {
			// Load proved this connector had no token before Ensure. The atomic
			// publisher can still report a late error after replacement became
			// visible, so remove any newly visible token before returning.
			if cleanupErr := connector.RemoveHookAPIToken(dataDir, name); cleanupErr != nil {
				return errors.Join(
					fmt.Errorf("connector reconcile: ensure scoped hook token: %w", err),
					fmt.Errorf("connector reconcile: remove ambiguously published scoped hook token: %w", cleanupErr),
				)
			}
			return fmt.Errorf("connector reconcile: ensure scoped hook token: %w", err)
		}
		tokenCreated = true
	}
	// Match the sidecar's least-privilege registration semantics: native hook
	// connectors use the connector-scoped token for hook calls and, where
	// supported by the vendor, native telemetry. Never write the gateway
	// master token into agent-owned config.
	opts.APIToken = hookToken
	opts.HookAPIToken = hookToken
	opts.HookAPITokenScoped = true

	if name == "opencode" {
		var lockSnapshot *connector.HookContractLockSnapshot
		if runtime.GOOS == "windows" {
			lockSnapshot, err = connector.CaptureHookContractLockSnapshot(dataDir)
			if err != nil {
				if tokenCreated {
					_ = connector.RemoveHookAPIToken(dataDir, "opencode")
				}
				return fmt.Errorf("connector reconcile opencode: capture contract-lock rollback point: %w", err)
			}
		}
		if err := reconcileOpenCodeRegistration(ctx, dataDir, conn, opts, lockSnapshot, previous, tokenCreated); err != nil {
			return fmt.Errorf("connector reconcile opencode: %w", err)
		}
	} else if name == "amp" && runtime.GOOS == "windows" {
		if err := reconcileAmpRegistration(ctx, dataDir, conn, opts, tokenCreated); err != nil {
			return fmt.Errorf("connector reconcile amp: %w", err)
		}
	} else {
		if err := connector.SetupRecordingCreatedDirs(ctx, conn, opts); err != nil {
			return fmt.Errorf("connector reconcile %s: %w", name, err)
		}
		entry := connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
		if err := connector.SaveHookContractLockEntry(dataDir, entry); err != nil {
			return fmt.Errorf("connector reconcile %s lock: %w", name, err)
		}
	}
	if name != "opencode" && !opts.ManagedEnterprise {
		if err := publishReconciledConnectorActive(dataDir, name); err != nil {
			return fmt.Errorf("connector reconcile %s: publish active runtime state: %w", name, err)
		}
	}
	return done(conn, opts)
}

// publishReconciledConnectorActive records name in the active roster, as the
// OpenCode path does. A reconcile with the gateway stopped (fail mode with no
// gateway running) writes hooks and a lock entry; when the roster does not
// name that connector, the gateway later finds a lock-only registration it
// has no authority to reconcile and can never start (GAP-1650). An unreadable
// roster is left for the gateway to report.
func publishReconciledConnectorActive(dataDir, name string) error {
	active, _, err := connector.ReadActiveConnectorState(dataDir)
	if err != nil {
		return nil
	}
	for _, existing := range active {
		if strings.EqualFold(existing, name) {
			return nil
		}
	}
	return connector.SaveActiveConnectors(dataDir, append(active, name))
}

func reconcileAmpRegistration(
	ctx context.Context,
	dataDir string,
	conn connector.Connector,
	opts connector.SetupOpts,
	tokenCreated bool,
) error {
	lockSnapshot, err := connector.CaptureHookContractLockSnapshot(dataDir)
	if err != nil {
		if tokenCreated {
			_ = connector.RemoveHookAPIToken(dataDir, "amp")
		}
		return fmt.Errorf("capture contract-lock rollback point: %w", err)
	}
	registrationSnapshot, err := connector.CapturePluginArtifactRegistrationSnapshot(opts, "amp")
	if err != nil {
		if tokenCreated {
			_ = connector.RemoveHookAPIToken(dataDir, "amp")
		}
		return fmt.Errorf("capture plugin rollback point: %w", err)
	}

	setupStarted := false
	lockPublishAttempted := false
	rollback := func(cause error) error {
		var rollbackErrs []error
		if setupStarted {
			if restoreErr := registrationSnapshot.Restore(); restoreErr != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("restore plugin transaction: %w", restoreErr))
			} else if registrationSnapshot.InitiallyEmpty() {
				if cleanErr := conn.VerifyClean(opts); cleanErr != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("verify plugin rollback: %w", cleanErr))
				}
			}
		}
		if lockPublishAttempted {
			if restoreErr := lockSnapshot.Restore(); restoreErr != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("restore exact contract-lock snapshot: %w", restoreErr))
			}
		}
		if tokenCreated {
			if removeErr := connector.RemoveHookAPIToken(dataDir, "amp"); removeErr != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("remove scoped token: %w", removeErr))
			}
		}
		if len(rollbackErrs) > 0 {
			return errors.Join(cause, fmt.Errorf("Amp setup rollback failed: %w", errors.Join(rollbackErrs...)))
		}
		return cause
	}

	setupStarted = true
	if err := connector.SetupRecordingCreatedDirs(ctx, conn, opts); err != nil {
		return rollback(fmt.Errorf("setup plugin and custody receipt: %w", err))
	}
	entry := connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
	lockPublishAttempted = true
	if err := connectorSaveAmpLock(dataDir, entry); err != nil {
		return rollback(fmt.Errorf("publish contract lock: %w", err))
	}
	return nil
}

func reconcileOpenCodeRegistration(
	ctx context.Context,
	dataDir string,
	conn connector.Connector,
	opts connector.SetupOpts,
	lockSnapshot *connector.HookContractLockSnapshot,
	previousLock connector.HookContractLockEntry,
	tokenCreated bool,
) error {
	previousActive, activeStateExisted, err := connector.ReadActiveConnectorState(dataDir)
	if err != nil {
		if tokenCreated {
			_ = connector.RemoveHookAPIToken(dataDir, "opencode")
		}
		return fmt.Errorf("read active runtime state: %w", err)
	}
	previouslyInactive := connector.ConnectorExplicitlyInactive(dataDir, "opencode")
	registrationSnapshot, err := connector.CaptureOpenCodeRegistrationSnapshot(opts)
	if err != nil {
		if tokenCreated {
			_ = connector.RemoveHookAPIToken(dataDir, "opencode")
		}
		return fmt.Errorf("capture registration rollback point: %w", err)
	}
	setupStarted := false
	lockPublishAttempted := false
	activePublishAttempted := false
	rollback := func(cause error) error {
		var rollbackErrs []error
		if setupStarted {
			if err := registrationSnapshot.Restore(); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("restore plugin transaction: %w", err))
			} else if registrationSnapshot.InitiallyEmpty() {
				if err := conn.VerifyClean(opts); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("verify plugin rollback: %w", err))
				}
			}
		}
		if lockPublishAttempted {
			if lockSnapshot != nil {
				if err := lockSnapshot.Restore(); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("restore exact contract-lock snapshot: %w", err))
				}
			} else if err := connector.ClearHookContractLockEntry(dataDir, "opencode"); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("clear contract lock: %w", err))
			} else if previousLock.Connector != "" {
				if err := connector.SaveFreshHookContractLockEntry(dataDir, previousLock); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("restore contract lock: %w", err))
				}
			}
		}
		if activePublishAttempted {
			if activeStateExisted {
				if err := connector.SaveActiveConnectors(dataDir, previousActive); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("restore active runtime state: %w", err))
				} else if previouslyInactive {
					if _, err := connector.MarkConnectorInactive(dataDir, "opencode"); err != nil {
						rollbackErrs = append(rollbackErrs, fmt.Errorf("restore inactive runtime marker: %w", err))
					}
				}
			} else if err := connector.RemoveActiveConnectorState(dataDir); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("remove active runtime state: %w", err))
			}
		}
		if tokenCreated {
			if err := connector.RemoveHookAPIToken(dataDir, "opencode"); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("remove scoped token: %w", err))
			}
		}
		if len(rollbackErrs) > 0 {
			return errors.Join(cause, fmt.Errorf("OpenCode setup rollback failed: %w", errors.Join(rollbackErrs...)))
		}
		return cause
	}

	setupStarted = true
	if err := connector.SetupRecordingCreatedDirs(ctx, conn, opts); err != nil {
		return rollback(fmt.Errorf("setup plugin and custody receipt: %w", err))
	}
	current, err := connector.OpenCodeRegistrationCurrent(opts)
	if err != nil || !current {
		if err == nil {
			err = errors.New("plugin and custody receipt are not current")
		}
		return rollback(fmt.Errorf("verify plugin publication: %w", err))
	}

	entry := connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
	lockPublishAttempted = true
	if err := connectorSaveOpenCodeLock(dataDir, entry); err != nil {
		return rollback(fmt.Errorf("publish contract lock: %w", err))
	}
	active := append(append([]string(nil), previousActive...), "opencode")
	activePublishAttempted = true
	if err := connectorSaveOpenCodeActive(dataDir, active); err != nil {
		return rollback(fmt.Errorf("publish active runtime state: %w", err))
	}

	loadedToken, tokenErr := connector.LoadHookAPIToken(dataDir, "opencode")
	registrationCurrent, registrationErr := connector.OpenCodeRegistrationCurrent(opts)
	activeCurrent := false
	for _, activeName := range connector.LoadActiveConnectors(dataDir) {
		if strings.EqualFold(activeName, "opencode") {
			activeCurrent = true
			break
		}
	}
	lockCurrent := connector.OpenCodeHookContractLockEntryCurrent(dataDir, entry)
	if registrationErr != nil || !registrationCurrent || tokenErr != nil || loadedToken != opts.APIToken ||
		!activeCurrent || !lockCurrent {
		return rollback(fmt.Errorf(
			"activation verification failed (plugin=%t plugin_err=%v token=%t token_err=%v active=%t lock=%t)",
			registrationCurrent,
			registrationErr,
			loadedToken == opts.APIToken,
			tokenErr,
			activeCurrent,
			lockCurrent,
		))
	}
	return nil
}

func runConnectorTeardown(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector teardown: no data directory configured (set --data-dir or run 'defenseclaw init')")
	}
	name := resolveActiveConnectorName(dataDir)
	if name == "codex" && connectorFlagConfigHome == "" {
		defer connector.PinConnectorConfigRootsForCommand(dataDir)()
	}
	restoreConfigHome, err := bindConnectorLifecycleConfigHome(name)
	if err != nil {
		return fmt.Errorf("connector teardown: %w", err)
	}
	defer restoreConfigHome()

	reg := newConnectorRegistryWithPlugins()
	conn, ok := reg.Get(name)
	if !ok {
		// A retired connector ID is never selectable or reconcilable. It
		// resolves only here so upgrade and uninstall can remove what an older
		// release wrote.
		conn, ok = connector.RetiredConnector(name)
	}
	if !ok {
		return fmt.Errorf("connector teardown: unknown connector %q (known: %s)",
			name, strings.Join(reg.Names(), ", "))
	}

	opts := resolveConnectorOpts(dataDir)
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	restoreState, err := connector.MarkConnectorInactive(dataDir, name)
	if err != nil {
		return fmt.Errorf("connector %s teardown: mark connector inactive: %w", name, err)
	}

	if err := runMarkedTeardown(ctx, name, conn, opts, restoreState); err != nil {
		if connectorFlagJSON {
			payload := map[string]any{
				"connector": name,
				"action":    "teardown",
				"ok":        false,
				"error":     err.Error(),
			}
			_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
			return fmt.Errorf("connector teardown failed")
		}
		return fmt.Errorf("connector %s teardown: %w", name, err)
	}

	// until 1.1: what the teardown of OpenHands or OmniGent could not remove
	// is listed as information, under the one removal notice.
	leftovers, removed := connector.RemovedConnectorLeftovers(name, opts)
	if connectorFlagJSON {
		payload := map[string]any{
			"connector": name,
			"action":    "teardown",
			"ok":        true,
		}
		if removed {
			payload["notice"] = connector.RemovedConnectorNotice
			payload["leftovers"] = append([]connector.RemovedLeftover{}, leftovers...)
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  %s %s teardown complete\n", Style(glyph("✓", "OK"), "fg=green", "bold"), name)
	if removed && len(leftovers) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), connector.RemovedConnectorNotice)
	}
	fmt.Fprint(cmd.OutOrStdout(), connector.FormatRemovedLeftovers(name, leftovers))
	return nil
}

// runMarkedTeardown runs the Teardown of a connector that is already marked
// inactive, and undoes that mark when the Teardown fails.
func runMarkedTeardown(ctx context.Context, name string, conn connector.Connector, opts connector.SetupOpts, restoreState func() error) error {
	if err := conn.Teardown(ctx, opts); err != nil {
		if restoreErr := restoreState(); restoreErr != nil {
			err = fmt.Errorf("%w; restore active connector state: %v", err, restoreErr)
		}
		return err
	}
	if name == "opencode" {
		// The empty folders the gateway's install watcher created go too.
		connector.RemoveOpenCodeWatcherCreatedDirs(opts.DataDir)
	}
	// Windows lock files stay after their lock; the idle ones this teardown
	// used beside the agent configs go now.
	connector.RemoveIdleFileLockSentinels()
	return nil
}

func runConnectorPruneOrphans(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector prune-orphans: no data directory configured (set --data-dir)")
	}
	// What is configured decides what is an orphan: without config.yaml or
	// with an unreadable connector state nothing is removed on a guess.
	if cfg == nil {
		return fmt.Errorf("connector prune-orphans: config.yaml is not loaded; nothing was removed")
	}
	configured := map[string]bool{}
	for _, name := range cfg.ActiveConnectors() {
		configured[strings.ToLower(strings.TrimSpace(name))] = true
	}
	active, _, err := connector.ReadActiveConnectorState(dataDir)
	if err != nil {
		return fmt.Errorf("connector prune-orphans: read the connector state: %w; nothing was removed", err)
	}
	for _, name := range active {
		configured[strings.ToLower(strings.TrimSpace(name))] = true
	}
	reg := newConnectorRegistryWithPlugins()
	names := reg.Names()
	if want := strings.ToLower(strings.TrimSpace(connectorFlagName)); want != "" {
		if _, ok := reg.Get(want); !ok {
			return fmt.Errorf("connector prune-orphans: unknown connector %q (known: %s)",
				want, strings.Join(names, ", "))
		}
		names = []string{want}
	}
	removed := map[string][]string{}
	failed := map[string]string{}
	for _, name := range names {
		if configured[name] {
			continue
		}
		conn, _ := reg.Get(name)
		paths, err := pruneOrphanedConnector(cmd.Context(), dataDir, name, conn)
		if err != nil {
			failed[name] = err.Error()
		} else if len(paths) > 0 {
			removed[name] = paths
		}
	}
	if connectorFlagJSON {
		payload := map[string]any{
			"action":  "prune-orphans",
			"ok":      len(failed) == 0,
			"removed": removed,
			"failed":  failed,
		}
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(payload); err != nil {
			return err
		}
	} else {
		for _, name := range names {
			if paths := removed[name]; len(paths) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s %s is not configured: removed its DefenseClaw hook entries from %s\n",
					Style(glyph("✓", "OK"), "fg=green", "bold"), name, strings.Join(paths, ", "))
			}
			if reason, ok := failed[name]; ok {
				fmt.Fprintf(cmd.ErrOrStderr(), "  %s: %s\n", name, reason)
			}
		}
	}
	if len(failed) > 0 {
		failedNames := make([]string, 0, len(failed))
		for _, name := range names {
			if _, ok := failed[name]; ok {
				failedNames = append(failedNames, name)
			}
		}
		return fmt.Errorf("connector prune-orphans: could not remove the hook entries of %s",
			strings.Join(failedNames, ", "))
	}
	return nil
}

// pruneOrphanedConnector tears down name, which is not configured, when its
// agent config still holds DefenseClaw hook entries for dataDir, and returns
// the config files they were in.
func pruneOrphanedConnector(ctx context.Context, dataDir, name string, conn connector.Connector) ([]string, error) {
	if name == "codex" && connectorFlagConfigHome == "" {
		defer connector.PinConnectorConfigRootsForCommand(dataDir)()
	}
	restoreConfigHome, err := bindConnectorLifecycleConfigHome(name)
	if err != nil {
		return nil, err
	}
	defer restoreConfigHome()
	opts := resolveConnectorOptsFor(dataDir, name)
	paths, err := connector.OrphanedHookConfigPaths(conn, opts)
	if err != nil || len(paths) == 0 {
		return nil, err
	}
	restoreState, err := connector.MarkConnectorInactive(dataDir, name)
	if err != nil {
		return nil, fmt.Errorf("mark connector inactive: %w", err)
	}
	if err := runMarkedTeardown(ctx, name, conn, opts, restoreState); err != nil {
		return nil, err
	}
	return paths, nil
}

func runConnectorPrepareRollback(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector prepare-rollback: no data directory configured (set --data-dir)")
	}
	reg := newConnectorRegistryWithPlugins()
	names := reg.Names()
	if connectorFlagName != "" {
		if _, ok := reg.Get(connectorFlagName); !ok {
			return fmt.Errorf("connector prepare-rollback: unknown connector %q (known: %s)",
				connectorFlagName, strings.Join(names, ", "))
		}
		names = []string{connectorFlagName}
	}
	opts := resolveConnectorOpts(dataDir)
	converted := map[string]int{}
	failed := map[string]string{}
	for _, name := range names {
		conn, _ := reg.Get(name)
		if connectorRollbackRestore {
			restorer, ok := conn.(connector.HookRollbackRestorer)
			if !ok {
				continue
			}
			count, err := restorer.RestoreHooksAfterRollback(opts)
			if err != nil {
				failed[name] = err.Error()
			} else if count > 0 {
				converted[name] = count
			}
			continue
		}
		converter, ok := conn.(connector.HookRollbackConverter)
		if !ok {
			continue
		}
		count, err := converter.ConvertHooksForRollback(opts)
		if err != nil {
			failed[name] = err.Error()
			continue
		}
		if count > 0 {
			converted[name] = count
		}
	}
	if connectorFlagJSON {
		payload := map[string]any{
			"action":    "prepare-rollback",
			"ok":        len(failed) == 0,
			"converted": converted,
			"failed":    failed,
		}
		if connectorRollbackRestore {
			payload["restored"] = converted
			delete(payload, "converted")
		}
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(payload); err != nil {
			return err
		}
	} else {
		for _, name := range names {
			if count := converted[name]; count > 0 {
				if connectorRollbackRestore {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s: restored %d authenticated current-release hook entries\n", name, count)
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  %s %s: rewrote %d hook entries in the form earlier releases remove\n",
					Style(glyph("✓", "OK"), "fg=green", "bold"), name, count)
			}
			if reason, ok := failed[name]; ok {
				fmt.Fprintf(cmd.ErrOrStderr(), "  %s: %s\n", name, reason)
			}
		}
	}
	if len(failed) > 0 {
		failedNames := make([]string, 0, len(failed))
		for _, name := range names {
			if _, ok := failed[name]; ok {
				failedNames = append(failedNames, name)
			}
		}
		if connectorRollbackRestore {
			return fmt.Errorf("connector prepare-rollback --restore: protection could not be verified or restored for %s; recovery evidence retained",
				strings.Join(failedNames, ", "))
		}
		return fmt.Errorf("connector prepare-rollback: could not rewrite the hook entries of %s",
			strings.Join(failedNames, ", "))
	}
	return nil
}

func runConnectorVerify(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector verify: no data directory configured (set --data-dir or run 'defenseclaw init')")
	}
	name := resolveActiveConnectorName(dataDir)
	if name == "codex" && connectorFlagConfigHome == "" {
		defer connector.PinConnectorConfigRootsForCommand(dataDir)()
	}
	restoreConfigHome, err := bindConnectorLifecycleConfigHome(name)
	if err != nil {
		return fmt.Errorf("connector verify: %w", err)
	}
	defer restoreConfigHome()

	reg := newConnectorRegistryWithPlugins()
	conn, ok := reg.Get(name)
	if !ok {
		// Legacy verification pairs with the retired teardown path above.
		conn, ok = connector.RetiredConnector(name)
	}
	if !ok {
		if !reg.NotShipped(name) {
			// A plugin directory declares this name (or plugin discovery
			// failed), so it may be an installed plugin that did not load.
			// Exit 2 would let uninstall skip its teardown and strand the
			// plugin's hooks; report it as not verifiable instead.
			fmt.Fprintf(cmd.ErrOrStderr(),
				"connector verify: connector %q is not loaded, but a plugin may provide it; fix the plugin under the configured plugin directory and retry\n",
				name)
			connectorExit(1)
			return nil
		}
		// Map "unknown connector" to exit code 2 (config error), distinct
		// from "connector dirty" (exit 1). Cobra surfaces RunE errors as
		// exit 1 by default, so we need to bypass cobra and call os.Exit.
		fmt.Fprintf(cmd.ErrOrStderr(), "connector verify: unknown connector %q (known: %s)\n",
			name, strings.Join(reg.Names(), ", "))
		connectorExit(2)
		return nil
	}

	opts := resolveConnectorOpts(dataDir)
	verifyErr := conn.VerifyClean(opts)

	if connectorFlagJSON {
		payload := map[string]any{
			"connector": name,
			"action":    "verify",
			"clean":     verifyErr == nil,
		}
		if verifyErr != nil {
			payload["residue"] = verifyErr.Error()
		}
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
		if verifyErr != nil {
			connectorExit(1)
		}
		return nil
	}

	if verifyErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s %s: %v\n", Style(glyph("✗", "X"), "fg=red", "bold"), name, verifyErr)
		connectorExit(1)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  %s %s: no residual DefenseClaw state detected\n", Style(glyph("✓", "OK"), "fg=green", "bold"), name)
	return nil
}

// connectorBackup is one entry returned by `connector list-backups`.
type connectorBackup struct {
	Connector string `json:"connector"`
	Path      string `json:"path"`
	Filename  string `json:"filename"`
	SizeBytes int64  `json:"size_bytes"`
}

// knownConnectorBackups maps backup filename → connector name. Centralised
// here so that adding a new built-in connector is a one-line change.
var knownConnectorBackups = map[string]string{
	"zeptoclaw_backup.json":  "zeptoclaw",
	"claudecode_backup.json": "claudecode",
	"codex_backup.json":      "codex",
	// OpenClaw stores its backup as <claw_config>.pristine *next to* the
	// claw config file, not under the data directory. discoverOpenClawBackup
	// handles that case below.
}

// discoverOpenClawBackup checks for the OpenClaw pristine backup, which
// lives at the same path as the claw config file with a `.pristine`
// suffix. Returns nil when the backup is missing or unreadable.
func discoverOpenClawBackup() *connectorBackup {
	if cfg == nil || cfg.Claw.ConfigFile == "" {
		return nil
	}
	path := cfg.Claw.ConfigFile + ".pristine"
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil
	}
	return &connectorBackup{
		Connector: "openclaw",
		Path:      path,
		Filename:  filepath.Base(path),
		SizeBytes: info.Size(),
	}
}

func runConnectorListBackups(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector list-backups: no data directory configured (set --data-dir or run 'defenseclaw init')")
	}

	backups := make([]connectorBackup, 0, len(knownConnectorBackups)+1)

	for filename, name := range knownConnectorBackups {
		full := filepath.Join(dataDir, filename)
		info, err := os.Stat(full)
		if err != nil || info.IsDir() {
			continue
		}
		backups = append(backups, connectorBackup{
			Connector: name,
			Path:      full,
			Filename:  filename,
			SizeBytes: info.Size(),
		})
	}

	managed, err := discoverManagedConnectorBackups(dataDir)
	if err != nil {
		return err
	}
	backups = append(backups, managed...)

	if oc := discoverOpenClawBackup(); oc != nil {
		backups = append(backups, *oc)
	}

	sort.Slice(backups, func(i, j int) bool {
		if backups[i].Connector != backups[j].Connector {
			return backups[i].Connector < backups[j].Connector
		}
		return backups[i].Path < backups[j].Path
	})

	if connectorFlagJSON {
		payload := map[string]any{
			"data_dir": dataDir,
			"count":    len(backups),
			"backups":  backups,
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
	}

	out := cmd.OutOrStdout()
	if len(backups) == 0 {
		fmt.Fprintf(out, "no connector backups found under %s\n", dataDir)
		return nil
	}
	hdr := fmt.Sprintf("%-12s  %-60s  %s", "CONNECTOR", "PATH", "SIZE")
	fmt.Fprintln(out, Bold(hdr))
	for _, b := range backups {
		fmt.Fprintf(out, "%-12s  %-60s  %d\n", b.Connector, b.Path, b.SizeBytes)
	}
	return nil
}

func discoverManagedConnectorBackups(dataDir string) ([]connectorBackup, error) {
	root := filepath.Join(dataDir, "connector_backups")
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("connector list-backups: stat managed backup dir: %w", err)
	}
	if !info.IsDir() {
		return nil, nil
	}

	var backups []connectorBackup
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return statErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = filepath.Base(path)
		}
		parts := strings.Split(rel, string(filepath.Separator))
		connectorName := "unknown"
		if len(parts) > 1 && strings.TrimSpace(parts[0]) != "" {
			connectorName = parts[0]
		}
		backups = append(backups, connectorBackup{
			Connector: connectorName,
			Path:      path,
			Filename:  filepath.Join("connector_backups", rel),
			SizeBytes: info.Size(),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("connector list-backups: walk managed backup dir: %w", err)
	}
	return backups, nil
}
