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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseHookTargetsWaitTimeout is the bounded window the hook-guardian
// will fsnotify-wait for a missing targets.yaml before returning a
// distinguishable error. See spec 003 (docs/specs/003-windows-deferred-config/)
// requirements.md REQ-14 + REQ-29. Kept as a package-level `var` (not a
// const) so the timeout-path CI test can shorten it via a build-tag override
// file; there is no envvar-configurable path — an operator cannot silently
// extend the cap to weeks and mask a broken UCB pipeline as still-installing.
var enterpriseHookTargetsWaitTimeout = 24 * time.Hour

// enterpriseHookTargetsWaitPoll is the interval at which the wait loop
// re-checks the manifest even if no fsnotify event fired. Defensive against
// missed events (Windows fsnotify can drop events under load) and against
// non-inotify filesystems (network shares) that never fire events at all.
var enterpriseHookTargetsWaitPoll = 30 * time.Second

var (
	enterpriseHookConnector     string
	enterpriseHookUser          string
	enterpriseHookUserHome      string
	enterpriseHookUID           int
	enterpriseHookGID           int
	enterpriseHookSID           string
	enterpriseHookDataDir       string
	enterpriseHookAPIAddr       string
	enterpriseHookProxyAddr     string
	enterpriseHookAgentVersion  string
	enterpriseHookManifest      string
	enterpriseHookJSON          bool
	enterpriseHookWatchInterval time.Duration
	enterpriseHookWatchDebounce time.Duration
	enterpriseHookWatchSettle   time.Duration

	enterpriseHooksRuntimeGOOS               = func() string { return runtime.GOOS }
	enterpriseHooksPlatformPreflight         = enterpriseHooksNativePlatformPreflight
	enterpriseHooksMutationIdentityPreflight = enterpriseHooksNativeMutationIdentityPreflight
	enterpriseHooksRootPersistentPreRun      = enterpriseHooksNativePersistentPreRun
	// Default the "full" enterprise hooks pre-run to the no-audit variant. The
	// hook-guardian's `enterprise hooks watch` runs as a long-lived daemon
	// beside the main gateway; the main gateway already owns audit.db in RW
	// mode, and SQLite cannot accept a second RW owner. The enterprise hooks
	// pathway (watch / install / uninstall / reconcile) does not use
	// auditStore or auditLog anywhere, so skipping the open removes dead work
	// and avoids the consistent SQLITE_BUSY crash the guardian would hit. The
	// seam remains overridable so lifecycle tests keep their custom pre-runs.
	enterpriseHooksFullRootPersistentPreRun   = rootPersistentPreRunNoAuditE
	enterpriseHooksConfigOnlyPersistentPreRun = func(*cobra.Command, []string) error {
		return loadGatewayCommandConfigOnly()
	}
	enterpriseHooksPluginRegistryFactory       = newConnectorRegistryWithPlugins
	enterpriseHooksCertifiedRegistryFactory    = newWindowsEnterpriseCertifiedConnectorRegistry
	enterpriseHooksInstallRunE                 = runEnterpriseHooksInstall
	enterpriseHooksUninstallRunE               = runEnterpriseHooksUninstall
	enterpriseHooksReconcileRunE               = runEnterpriseHooksReconcile
	enterpriseHooksWatchRunE                   = runEnterpriseHooksWatch
	enterpriseHooksStatusRunE                  = runEnterpriseHooksStatus
	enterpriseHooksVerifyRunE                  = runEnterpriseHooksVerify
	enterpriseHookAuthorizationOwnershipSetter = setEnterpriseHookAuthorizationOwnership
	enterpriseHookAuthorizationDirTrustCheck   = func(path string) error {
		return managed.ValidateTrustedRuntimeDir(path, "hook guardian authorization directory")
	}
	enterpriseHookAuthorizationFileTrustCheck = func(path string) error {
		return managed.ValidateTrustedFilePath(path, "hook guardian authorization")
	}
	enterpriseHookGuardianStateFileTrustCheck = func(path string) error {
		return managed.ValidateTrustedServiceRuntimeFilePath(
			path,
			"hook guardian state",
			os.Getenv(managed.WindowsServiceAccountEnv),
		)
	}
	enterpriseHooksRemoveManagedPolicy  = enterprisehooks.RemoveManagedPolicy
	enterpriseHookScopedTokenMinter     = enterpriseHookScopedToken
	enterpriseHookScopedOTLPTokenMinter = enterpriseHookScopedOTLPToken
)

const defaultEnterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
const hookGuardianStateFile = "hook_guardian_state.json"
const hookGuardianAuthorizationFile = managed.HookGuardianAuthorizationFile
const hookGuardianAuthorizationDirEnv = managed.HookGuardianAuthorizationDirEnv

const (
	enterpriseHookGuardianStateMaxBytes         int64 = 1 << 20
	enterpriseHookGuardianAuthorizationMaxBytes int64 = 4 << 20
	enterpriseHookWatchRepairRetryMin                 = time.Second
	enterpriseHookWatchRepairRetryMax                 = 15 * time.Second
)

var enterpriseCmd = &cobra.Command{
	Use:   "enterprise",
	Short: "Enterprise deployment maintenance commands",
	Long: `Enterprise maintenance commands for administrator-owned DefenseClaw
deployments. These commands are intended for root/MDM/systemd use, not for
standard users.`,
}

var enterpriseHooksCmd = &cobra.Command{
	Use:   "hooks",
	Short: "Install and repair per-user hook connectors",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := enterpriseHooksPlatformPreflight(); err != nil {
			return err
		}
		// Cobra runs only the nearest persistent pre-run hook. Chain the root
		// initializer explicitly so supported hosts retain config, audit, and
		// authorization initialization before any enterprise hook operation.
		return enterpriseHooksRootPersistentPreRun(cmd, args)
	},
}

func newEnterpriseHooksConnectorRegistry() *connector.Registry {
	if enterpriseHooksRuntimeGOOS() == "windows" &&
		cfg != nil &&
		managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return enterpriseHooksCertifiedRegistryFactory()
	}
	return enterpriseHooksPluginRegistryFactory()
}

func newWindowsEnterpriseCertifiedConnectorRegistry() *connector.Registry {
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(connector.NewCodexConnector())
	registry.RegisterBuiltin(connector.NewClaudeCodeConnector())
	return registry
}

var enterpriseHooksInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install or repair a hook-native connector for one interactive user",
	Long: `Install or repair DefenseClaw hook wiring for one interactive user's
agent configuration.

The hardened gateway service should not be granted write access to /home.
On Linux and macOS, run this command as root for each protected user or from an
MDM/system guardian. On native Windows, direct hook mutation is reserved for the
LocalSystem guardian; administrators use the enterprise windows lifecycle
commands. First-time installs require the agent's native hook config file to
already exist, so broad process discovery cannot create a new app profile from
scratch.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return enterpriseHooksInstallRunE(cmd, args)
	},
}

var enterpriseHooksUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove an owned administrator-managed hook registration",
	Long: `Remove one interactive user's DefenseClaw registration from the
administrator-managed hook policy. The command validates the protected policy
and ownership sidecar before mutation and refuses foreign or edited policy.
Per-user runtime files are retained for repair or forensic recovery.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return enterpriseHooksUninstallRunE(cmd, args)
	},
}

var enterpriseHooksReconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "Install or repair all enabled per-user hook targets from a manifest",
	Long: `Reconcile every enabled hook target from an administrator-owned manifest.

The manifest is the enterprise guardian's allow-list. It prevents a privileged
repair job from scanning every home directory or writing into service accounts
by accident. Each enabled target is installed or repaired independently; the
command reports every result and exits non-zero when any target fails.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return enterpriseHooksReconcileRunE(cmd, args)
	},
}

var enterpriseHooksWatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Continuously repair per-user hook targets from a manifest",
	Long: `Continuously watch manifest-scoped per-user hook targets and repair
tamper events through the hardened enterprise hook installer.

This command is intended for a root-owned system service. It watches only
directories derived from the administrator-owned manifest and keeps the
periodic reconcile interval as a backstop for missed filesystem events.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return enterpriseHooksWatchRunE(cmd, args)
	},
}

var enterpriseHooksStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Report cached guardian and protected authorization health",
	Long: `Report the last guardian reconcile and the independent administrator-owned
authorization ledger without changing either record.

Managed health is successful only when both records describe the same complete
reconcile. In non-managed mode this command reports enterprise enforcement as
disabled and does not change ordinary hook auto-heal behavior.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return enterpriseHooksStatusRunE(cmd, args)
	},
}

var enterpriseHooksVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify every enabled manifest target without repairing it",
	Long: `Perform a read-only live verification of every enabled target in the
administrator-owned manifest.

The command validates target identity, policy and authorization ownership,
canonical hook/runtime bytes, connector-scoped credentials, DACLs or modes,
hook contracts, and protected-ledger coverage. It exits non-zero when any
target or aggregate guardian control is unhealthy.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return enterpriseHooksVerifyRunE(cmd, args)
	},
}

func init() {
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookConnector, "connector", "",
		"Hook-native connector to install or repair (for example codex or claudecode)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookUser, "user", "",
		"Target local user name (resolves home, uid, and gid)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookUserHome, "user-home", "",
		"Target user's home directory (required when --user is omitted)")
	enterpriseHooksInstallCmd.Flags().IntVar(&enterpriseHookUID, "uid", -1,
		"Target user uid (defaults to --user lookup or user-home owner)")
	enterpriseHooksInstallCmd.Flags().IntVar(&enterpriseHookGID, "gid", -1,
		"Target user gid (defaults to --user lookup or user-home owner)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookSID, "sid", "",
		"Target Windows user SID (defaults to --user lookup or user-home owner)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookDataDir, "data-dir", "",
		"Per-user DefenseClaw data dir for hook scripts and token (default: <user-home>/.defenseclaw; native Windows managed Claude requires this exact path)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookAPIAddr, "api-addr", "",
		"Local gateway API host:port used by hook scripts (default: 127.0.0.1:<gateway.api_port>)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookProxyAddr, "proxy-addr", "",
		"Local guardrail proxy host:port (default: 127.0.0.1:<guardrail.port>)")
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookAgentVersion, "agent-version", "",
		"Raw local agent version used for hook-contract validation")
	enterpriseHooksInstallCmd.Flags().BoolVar(&enterpriseHookJSON, "json", false,
		"Emit machine-readable JSON")
	enterpriseHooksUninstallCmd.Flags().StringVar(&enterpriseHookConnector, "connector", "",
		"Administrator-managed connector to remove (built-in codex or claudecode on native Windows)")
	enterpriseHooksUninstallCmd.Flags().StringVar(&enterpriseHookUser, "user", "",
		"Target local user name (resolves home and SID)")
	enterpriseHooksUninstallCmd.Flags().StringVar(&enterpriseHookUserHome, "user-home", "",
		"Target user's home directory (required when --user is omitted)")
	enterpriseHooksUninstallCmd.Flags().IntVar(&enterpriseHookUID, "uid", -1,
		"Target user uid (Unix compatibility; defaults to user-home owner)")
	enterpriseHooksUninstallCmd.Flags().IntVar(&enterpriseHookGID, "gid", -1,
		"Target user gid (Unix compatibility; defaults to user-home owner)")
	enterpriseHooksUninstallCmd.Flags().StringVar(&enterpriseHookSID, "sid", "",
		"Target Windows user SID (defaults to --user lookup or user-home owner)")
	enterpriseHooksUninstallCmd.Flags().StringVar(&enterpriseHookDataDir, "data-dir", "",
		"Per-user DefenseClaw data dir associated with the registration (native Windows managed Claude accepts only <user-home>/.defenseclaw)")
	enterpriseHooksUninstallCmd.Flags().BoolVar(&enterpriseHookJSON, "json", false,
		"Emit machine-readable JSON")

	enterpriseHooksReconcileCmd.Flags().StringVar(&enterpriseHookManifest, "manifest", defaultEnterpriseHookManifest,
		"YAML manifest of per-user hook targets")
	enterpriseHooksReconcileCmd.Flags().StringVar(&enterpriseHookAPIAddr, "api-addr", "",
		"Local gateway API host:port used by hook scripts (default: 127.0.0.1:<gateway.api_port>)")
	enterpriseHooksReconcileCmd.Flags().StringVar(&enterpriseHookProxyAddr, "proxy-addr", "",
		"Local guardrail proxy host:port (default: 127.0.0.1:<guardrail.port>)")
	enterpriseHooksReconcileCmd.Flags().BoolVar(&enterpriseHookJSON, "json", false,
		"Emit machine-readable JSON")

	enterpriseHooksWatchCmd.Flags().StringVar(&enterpriseHookManifest, "manifest", defaultEnterpriseHookManifest,
		"YAML manifest of per-user hook targets")
	enterpriseHooksWatchCmd.Flags().StringVar(&enterpriseHookAPIAddr, "api-addr", "",
		"Local gateway API host:port used by hook scripts (default: 127.0.0.1:<gateway.api_port>)")
	enterpriseHooksWatchCmd.Flags().StringVar(&enterpriseHookProxyAddr, "proxy-addr", "",
		"Local guardrail proxy host:port (default: 127.0.0.1:<guardrail.port>)")
	enterpriseHooksWatchCmd.Flags().DurationVar(&enterpriseHookWatchInterval, "interval", time.Minute,
		"Periodic reconcile backstop interval")
	enterpriseHooksWatchCmd.Flags().DurationVar(&enterpriseHookWatchDebounce, "debounce", 750*time.Millisecond,
		"Filesystem-event debounce before reconcile")
	enterpriseHooksWatchCmd.Flags().DurationVar(&enterpriseHookWatchSettle, "settle", 2*time.Second,
		"Post-reconcile quiet window: fsnotify events observed within this window after a reconcile completes are ignored (the guardian's own writes into watched dirs would otherwise loop-trigger reconcile forever)")

	enterpriseHooksStatusCmd.Flags().StringVar(&enterpriseHookManifest, "manifest", defaultEnterpriseHookManifest,
		"Expected YAML manifest path recorded by the guardian")
	enterpriseHooksStatusCmd.Flags().BoolVar(&enterpriseHookJSON, "json", false,
		"Emit machine-readable JSON")

	enterpriseHooksVerifyCmd.Flags().StringVar(&enterpriseHookManifest, "manifest", defaultEnterpriseHookManifest,
		"YAML manifest of per-user hook targets")
	enterpriseHooksVerifyCmd.Flags().StringVar(&enterpriseHookAPIAddr, "api-addr", "",
		"Local gateway API host:port used by hook scripts (default: 127.0.0.1:<gateway.api_port>)")
	enterpriseHooksVerifyCmd.Flags().StringVar(&enterpriseHookProxyAddr, "proxy-addr", "",
		"Local guardrail proxy host:port (default: 127.0.0.1:<guardrail.port>)")
	enterpriseHooksVerifyCmd.Flags().BoolVar(&enterpriseHookJSON, "json", false,
		"Emit machine-readable JSON")

	enterpriseHooksCmd.AddCommand(enterpriseHooksInstallCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksUninstallCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksReconcileCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksWatchCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksStatusCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksVerifyCmd)
	enterpriseCmd.AddCommand(enterpriseHooksCmd)
	rootCmd.AddCommand(enterpriseCmd)
}

func runEnterpriseHooksUninstall(cmd *cobra.Command, _ []string) error {
	target := enterpriseHookTarget{uid: -1, gid: -1, sid: strings.TrimSpace(enterpriseHookSID)}
	var err error
	if target.sid == "" || strings.TrimSpace(enterpriseHookUser) != "" || strings.TrimSpace(enterpriseHookUserHome) != "" {
		target, err = resolveEnterpriseHookTarget()
		if err != nil {
			return enterpriseHooksUninstallError(cmd, err)
		}
	}
	err = enterpriseHooksRemoveManagedPolicy(cmd.Context(), enterprisehooks.InstallOptions{
		ConnectorName: enterpriseHookConnector,
		UserHome:      target.home,
		OwnerUID:      target.uid,
		OwnerGID:      target.gid,
		OwnerSID:      target.sid,
		DataDir:       enterpriseHookDataDir,
	})
	if err != nil {
		return enterpriseHooksUninstallError(cmd, err)
	}
	if enterpriseHookJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"ok": true, "connector": strings.TrimSpace(enterpriseHookConnector), "user_home": target.home,
		})
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  %s %s managed hooks removed for %s\n", Style("✓", "fg=green", "bold"), strings.TrimSpace(enterpriseHookConnector), target.home)
	return nil
}

func enterpriseHooksUninstallError(cmd *cobra.Command, err error) error {
	if enterpriseHookJSON {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"ok": false, "error": err.Error()})
		return fmt.Errorf("enterprise hooks uninstall failed")
	}
	return err
}

func runEnterpriseHooksInstall(cmd *cobra.Command, _ []string) error {
	if cfg == nil {
		return enterpriseHooksInstallError(cmd, fmt.Errorf("enterprise hooks install: config is not loaded"))
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return enterpriseHooksInstallError(cmd, err)
	}
	if err := validateEnterpriseHookManagedRuntime(); err != nil {
		return enterpriseHooksInstallError(cmd, err)
	}
	target, err := resolveEnterpriseHookTarget()
	if err != nil {
		return enterpriseHooksInstallError(cmd, err)
	}
	apiAddr := strings.TrimSpace(enterpriseHookAPIAddr)
	if apiAddr == "" {
		apiAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Gateway.APIPort)
	}
	proxyAddr := strings.TrimSpace(enterpriseHookProxyAddr)
	if proxyAddr == "" {
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Guardrail.Port)
	}
	token, err := enterpriseHookScopedTokenMinter(cfg.DataDir, enterpriseHookConnector)
	if err != nil {
		return enterpriseHooksInstallError(cmd, err)
	}
	otlpToken, err := enterpriseHookScopedOTLPTokenMinter(cfg.DataDir, enterpriseHookConnector)
	if err != nil {
		return enterpriseHooksInstallError(cmd, err)
	}

	previousProtection, err := previousEnterpriseHookProtection(
		cfg.DataDir,
		enterpriseHookUser,
		target.home,
		target.sid,
		enterpriseHookConnector,
	)
	if err != nil {
		return enterpriseHooksInstallError(cmd, err)
	}
	opts := enterprisehooks.InstallOptions{
		ConnectorName:                      enterpriseHookConnector,
		UserHome:                           target.home,
		OwnerUID:                           target.uid,
		OwnerGID:                           target.gid,
		OwnerSID:                           target.sid,
		DataDir:                            enterpriseHookDataDir,
		APIAddr:                            apiAddr,
		ProxyAddr:                          proxyAddr,
		APIToken:                           token,
		OTLPPathToken:                      otlpToken,
		HookFailMode:                       cfg.EffectiveHookFailModeForConnector(enterpriseHookConnector),
		GuardrailMode:                      cfg.EffectiveGuardrailModeForConnector(enterpriseHookConnector),
		HILTEnabled:                        cfg.EffectiveHILTForConnector(enterpriseHookConnector).Enabled,
		AgentVersion:                       enterpriseHookAgentVersion,
		WorkspaceDir:                       cfg.ConnectorWorkspaceDir(),
		Registry:                           newEnterpriseHooksConnectorRegistry(),
		AllowMissingHookConfigRepair:       previousProtection.PreviouslyProtected,
		RecoveryHookContractLockUpdatedAt:  previousProtection.HookContractLockUpdatedAt,
		RecoveryHookContractEntryUpdatedAt: previousProtection.HookContractEntryUpdatedAt,
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	result, err := enterprisehooks.Install(ctx, opts)
	if err != nil {
		return enterpriseHooksInstallError(cmd, err)
	}
	if enterpriseHookJSON {
		payload := map[string]any{"ok": true, "result": result}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  %s %s hooks installed for %s\n", Style("✓", "fg=green", "bold"), result.Connector, result.UserHome)
	return nil
}

func enterpriseHooksInstallError(cmd *cobra.Command, err error) error {
	if enterpriseHookJSON {
		payload := map[string]any{"ok": false, "error": err.Error()}
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
		return fmt.Errorf("enterprise hooks install failed")
	}
	return err
}

type enterpriseHookReconcileRow struct {
	User      string                         `json:"user,omitempty"`
	UserHome  string                         `json:"user_home,omitempty"`
	SID       string                         `json:"sid,omitempty"`
	Connector string                         `json:"connector"`
	OK        bool                           `json:"ok"`
	Error     string                         `json:"error,omitempty"`
	Result    *enterprisehooks.InstallResult `json:"result,omitempty"`
}

type enterpriseHookReconcileRun struct {
	Manifest            string
	Rows                []enterpriseHookReconcileRow
	Failures            int
	StateErr            error
	WatchDirs           []string
	WatchExclusiveFiles []string // DC-only writers: react to any event
	WatchSharedFiles    []string // agent + DC writers: react only to Create/Remove/Rename
}

func runEnterpriseHooksReconcile(cmd *cobra.Command, _ []string) error {
	run, err := runEnterpriseHookReconcileOnce(cmd.Context())
	if err != nil {
		return err
	}
	if enterpriseHookJSON {
		payload := map[string]any{
			"ok":       run.Failures == 0 && run.StateErr == nil,
			"manifest": run.Manifest,
			"results":  run.Rows,
		}
		if run.StateErr != nil {
			payload["state_error"] = run.StateErr.Error()
		}
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
		if run.Failures > 0 || run.StateErr != nil {
			if run.StateErr != nil {
				return fmt.Errorf("enterprise hooks reconcile state write failed: %w", run.StateErr)
			}
			return fmt.Errorf("enterprise hooks reconcile failed for %d target(s)", run.Failures)
		}
		return nil
	}

	for _, row := range run.Rows {
		label := row.Connector
		if row.User != "" {
			label += "@" + row.User
		} else if row.UserHome != "" {
			label += "@" + row.UserHome
		}
		if row.OK {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s reconciled\n", Style("✓", "fg=green", "bold"), label)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s %s: %s\n", Style("✗", "fg=red", "bold"), label, row.Error)
		}
	}
	if run.StateErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s hook guardian state: %s\n", Style("✗", "fg=red", "bold"), run.StateErr.Error())
		return fmt.Errorf("enterprise hooks reconcile state write failed: %w", run.StateErr)
	}
	if run.Failures > 0 {
		return fmt.Errorf("enterprise hooks reconcile failed for %d target(s)", run.Failures)
	}
	return nil
}

type enterpriseHookStatusReport struct {
	Enabled                       bool                                 `json:"enabled"`
	OK                            bool                                 `json:"ok"`
	StateFile                     string                               `json:"state_file"`
	AuthorizationFile             string                               `json:"authorization_file"`
	State                         *enterpriseHookGuardianState         `json:"state,omitempty"`
	Authorization                 *enterpriseHookGuardianAuthorization `json:"authorization,omitempty"`
	Verification                  []enterpriseHookReconcileRow         `json:"verification,omitempty"`
	ClaudeEffectivePolicyVerified bool                                 `json:"claude_effective_policy_verified"`
	Errors                        []string                             `json:"errors,omitempty"`
}

func runEnterpriseHooksStatus(cmd *cobra.Command, _ []string) error {
	report := enterpriseHookStatusReport{}
	if cfg == nil {
		return enterpriseHooksStatusError(cmd, report, fmt.Errorf("enterprise hooks status: config is not loaded"))
	}
	report.Enabled = managed.IsManagedEnterprise(cfg.DeploymentMode)
	report.StateFile = filepath.Join(strings.TrimSpace(cfg.DataDir), hookGuardianStateFile)
	report.AuthorizationFile = managed.HookGuardianAuthorizationPath(cfg.DataDir)
	if !report.Enabled {
		report.OK = true
		if enterpriseHookJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "  Enterprise hook enforcement: disabled (ordinary hook auto-heal unchanged)")
		return nil
	}

	state, stateExists, stateErr := loadEnterpriseHookGuardianState(cfg.DataDir)
	if stateErr != nil {
		report.Errors = append(report.Errors, stateErr.Error())
	} else if !stateExists {
		report.Errors = append(report.Errors, "hook guardian has not completed a reconcile")
	} else {
		report.State = &state
		report.Errors = append(report.Errors, enterpriseHookGuardianFailureIssues(state)...)
	}
	authorization, authorizationExists, authorizationErr := loadEnterpriseHookGuardianAuthorization(cfg.DataDir)
	if authorizationErr != nil {
		report.Errors = append(report.Errors, authorizationErr.Error())
	} else if !authorizationExists {
		report.Errors = append(report.Errors, "protected hook guardian authorization is missing")
	} else {
		report.Authorization = &authorization
	}
	if stateExists && authorizationExists && stateErr == nil && authorizationErr == nil {
		report.Errors = append(report.Errors, compareEnterpriseHookGuardianRecords(state, authorization, enterpriseHookManifest)...)
	}
	live, liveErr := runEnterpriseHookVerifyOnce(cmd.Context())
	if liveErr != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("live hook verification failed: %v", liveErr))
	} else {
		report.Verification = live.Rows
		report.ClaudeEffectivePolicyVerified =
			enterpriseHooksClaudeEffectivePolicyVerified(live.Rows)
		if live.AuthorizationErr != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("live protected authorization check failed: %v", live.AuthorizationErr))
		}
		for _, row := range live.Rows {
			if !row.OK {
				report.Errors = append(
					report.Errors,
					fmt.Sprintf("live verification failed for %s: %s", enterpriseHookTargetLabel(row), row.Error),
				)
			}
		}
	}
	report.OK = len(report.Errors) == 0
	if enterpriseHookJSON {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
			return err
		}
		if !report.OK {
			return fmt.Errorf("enterprise hooks status unhealthy")
		}
		return nil
	}
	if report.OK {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s enterprise hook guardian healthy (%d/%d targets verified)\n",
			Style("✓", "fg=green", "bold"), state.SuccessCount, state.TargetCount)
		return nil
	}
	for _, issue := range report.Errors {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s %s\n", Style("✗", "fg=red", "bold"), issue)
	}
	return fmt.Errorf("enterprise hooks status unhealthy")
}

func enterpriseHooksStatusError(cmd *cobra.Command, report enterpriseHookStatusReport, err error) error {
	report.OK = false
	report.Errors = append(report.Errors, err.Error())
	if enterpriseHookJSON {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(report)
		return fmt.Errorf("enterprise hooks status failed")
	}
	return err
}

func enterpriseHookGuardianFailureIssues(state enterpriseHookGuardianState) []string {
	issues := make([]string, 0, state.FailureCount)
	for _, row := range state.Results {
		if row.OK {
			continue
		}
		detail := strings.TrimSpace(row.Error)
		if detail == "" {
			detail = "no target error was recorded"
		}
		issues = append(
			issues,
			fmt.Sprintf("last guardian reconcile failed for %s: %s", enterpriseHookTargetLabel(row), detail),
		)
	}
	return issues
}

func loadEnterpriseHookGuardianState(dataDir string) (enterpriseHookGuardianState, bool, error) {
	path := filepath.Join(strings.TrimSpace(dataDir), hookGuardianStateFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return enterpriseHookGuardianState{}, false, nil
	}
	if err != nil {
		return enterpriseHookGuardianState{}, false, fmt.Errorf("inspect hook guardian state %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return enterpriseHookGuardianState{}, true, fmt.Errorf("hook guardian state is not a regular file: %s", path)
	}
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if err := enterpriseHookGuardianStateFileTrustCheck(path); err != nil {
			return enterpriseHookGuardianState{}, true, fmt.Errorf("validate hook guardian state %s: %w", path, err)
		}
	}
	data, err := readEnterpriseHookBoundedFile(
		path,
		info,
		enterpriseHookGuardianStateMaxBytes,
		"hook guardian state",
	)
	if err != nil {
		return enterpriseHookGuardianState{}, true, fmt.Errorf("read hook guardian state %s: %w", path, err)
	}
	var state enterpriseHookGuardianState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return enterpriseHookGuardianState{}, true, fmt.Errorf("parse hook guardian state %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return enterpriseHookGuardianState{}, true, fmt.Errorf("parse hook guardian state %s: trailing content", path)
	}
	if state.Version != 1 || state.TargetCount < 0 || state.SuccessCount < 0 || state.FailureCount < 0 ||
		state.SuccessCount+state.FailureCount != state.TargetCount || len(state.Results) != state.TargetCount {
		return enterpriseHookGuardianState{}, true, fmt.Errorf("hook guardian state %s has invalid schema or target counts", path)
	}
	return state, true, nil
}

func compareEnterpriseHookGuardianRecords(state enterpriseHookGuardianState, authorization enterpriseHookGuardianAuthorization, expectedManifest string) []string {
	var issues []string
	now := time.Now()
	if err := managed.ValidateHookGuardianFreshness(state.UpdatedAt, now); err != nil {
		issues = append(issues, fmt.Sprintf("hook guardian state is not fresh: %v", err))
	}
	if err := managed.ValidateHookGuardianFreshness(authorization.UpdatedAt, now); err != nil {
		issues = append(issues, fmt.Sprintf("protected guardian authorization is not fresh: %v", err))
	}
	if !state.OK || state.FailureCount != 0 || state.SuccessCount != state.TargetCount {
		issues = append(issues, fmt.Sprintf("last guardian reconcile is incomplete (%d/%d targets succeeded)", state.SuccessCount, state.TargetCount))
	}
	if !authorization.OK || authorization.FailureCount != 0 || authorization.SuccessCount != authorization.TargetCount {
		issues = append(issues, fmt.Sprintf("protected guardian authorization is incomplete (%d/%d targets succeeded)", authorization.SuccessCount, authorization.TargetCount))
	}
	if state.TargetCount != authorization.TargetCount || state.SuccessCount != authorization.SuccessCount ||
		state.FailureCount != authorization.FailureCount {
		issues = append(issues, "guardian state and protected authorization target counts do not match")
	}
	if state.UpdatedAt == "" || authorization.UpdatedAt == "" || state.UpdatedAt != authorization.UpdatedAt {
		issues = append(issues, "guardian state and protected authorization do not identify the same reconcile")
	}
	if expected := strings.TrimSpace(expectedManifest); expected != "" && !sameEnterpriseHookPath(state.Manifest, expected) {
		issues = append(issues, fmt.Sprintf("guardian state records manifest %s, expected %s", state.Manifest, expected))
	}
	if state.OK && authorization.OK {
		issues = append(
			issues,
			compareEnterpriseHookProtectedTargetSets(state.Results, authorization.ProtectedTargets)...,
		)
	} else {
		for _, row := range state.Results {
			if !row.OK {
				continue
			}
			covered := false
			for _, protected := range authorization.ProtectedTargets {
				if enterpriseHookRowMatches(protected, row.User, row.UserHome, row.SID, strings.ToLower(strings.TrimSpace(row.Connector))) {
					covered = true
					break
				}
			}
			if !covered {
				issues = append(issues, fmt.Sprintf("protected authorization does not cover %s", enterpriseHookTargetLabel(row)))
			}
		}
	}
	return issues
}

func compareEnterpriseHookProtectedTargetSets(expected, actual []enterpriseHookReconcileRow) []string {
	expectedByKey := make(map[string]enterpriseHookReconcileRow, len(expected))
	actualByKey := make(map[string]enterpriseHookReconcileRow, len(actual))
	var issues []string
	for _, row := range expected {
		key := enterpriseHookProtectedTargetKey(row)
		if key == "" {
			issues = append(issues, fmt.Sprintf("current enabled target is incomplete: %s", enterpriseHookTargetLabel(row)))
			continue
		}
		if _, duplicate := expectedByKey[key]; duplicate {
			issues = append(issues, fmt.Sprintf("current enabled target is duplicated: %s", enterpriseHookTargetLabel(row)))
			continue
		}
		expectedByKey[key] = row
	}
	for _, row := range actual {
		key := enterpriseHookProtectedTargetKey(row)
		if key == "" {
			issues = append(issues, fmt.Sprintf("protected authorization contains an incomplete target: %s", enterpriseHookTargetLabel(row)))
			continue
		}
		if _, duplicate := actualByKey[key]; duplicate {
			issues = append(issues, fmt.Sprintf("protected authorization contains a duplicate target: %s", enterpriseHookTargetLabel(row)))
			continue
		}
		actualByKey[key] = row
	}
	for key, row := range expectedByKey {
		if _, covered := actualByKey[key]; !covered {
			issues = append(issues, fmt.Sprintf("protected authorization does not cover %s", enterpriseHookTargetLabel(row)))
		}
	}
	for key, row := range actualByKey {
		if _, enabled := expectedByKey[key]; !enabled {
			issues = append(issues, fmt.Sprintf("protected authorization contains extra or stale target %s", enterpriseHookTargetLabel(row)))
		}
	}
	sort.Strings(issues)
	return issues
}

func sameEnterpriseHookPath(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(absA), filepath.Clean(absB))
	}
	return filepath.Clean(absA) == filepath.Clean(absB)
}

func enterpriseHookTargetLabel(row enterpriseHookReconcileRow) string {
	label := strings.TrimSpace(row.Connector)
	if row.SID != "" {
		return label + "@" + row.SID
	}
	if row.User != "" {
		return label + "@" + row.User
	}
	if row.UserHome != "" {
		return label + "@" + row.UserHome
	}
	return label
}

type enterpriseHookVerifyRun struct {
	Manifest         string
	Rows             []enterpriseHookReconcileRow
	Failures         int
	AuthorizationErr error
}

func runEnterpriseHooksVerify(cmd *cobra.Command, _ []string) error {
	run, err := runEnterpriseHookVerifyOnce(cmd.Context())
	if err != nil {
		return err
	}
	ok := run.Failures == 0 && run.AuthorizationErr == nil
	if enterpriseHookJSON {
		payload := map[string]any{
			"ok":                               ok,
			"manifest":                         run.Manifest,
			"results":                          run.Rows,
			"claude_effective_policy_verified": enterpriseHooksClaudeEffectivePolicyVerified(run.Rows),
		}
		if run.AuthorizationErr != nil {
			payload["authorization_error"] = run.AuthorizationErr.Error()
		}
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(payload); err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("enterprise hooks verify failed")
		}
		return nil
	}
	for _, row := range run.Rows {
		if row.OK {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s verified\n", Style("✓", "fg=green", "bold"), enterpriseHookTargetLabel(row))
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s %s: %s\n", Style("✗", "fg=red", "bold"), enterpriseHookTargetLabel(row), row.Error)
		}
	}
	if run.AuthorizationErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s protected authorization: %s\n", Style("✗", "fg=red", "bold"), run.AuthorizationErr)
	}
	if !ok {
		return fmt.Errorf("enterprise hooks verify failed for %d target(s)", run.Failures)
	}
	return nil
}

// enterpriseHooksClaudeEffectivePolicyVerified deliberately remains false for
// generic guardian verification rows. An OK row proves protected local policy
// and runtime integrity, but Claude's first-source-wins behavior can only be
// certified by a distinct approved-client invocation. That lifecycle evidence
// is persisted separately and must never be inferred here.
func enterpriseHooksClaudeEffectivePolicyVerified(rows []enterpriseHookReconcileRow) bool {
	_ = rows
	return false
}

func runEnterpriseHookVerifyOnce(ctx context.Context) (enterpriseHookVerifyRun, error) {
	run := enterpriseHookVerifyRun{Manifest: enterpriseHookManifest}
	if cfg == nil {
		return run, fmt.Errorf("enterprise hooks verify: config is not loaded")
	}
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if err := managed.ValidateTrustedFilePath(enterpriseHookManifest, "hook guardian manifest"); err != nil {
			return run, fmt.Errorf("enterprise hooks verify: manifest trust check failed: %w", err)
		}
		if err := validateEnterpriseHookManagedRuntime(); err != nil {
			return run, err
		}
	}
	manifest, err := enterprisehooks.LoadManifest(enterpriseHookManifest)
	if err != nil {
		return run, err
	}
	authorization, exists, authorizationErr := loadEnterpriseHookGuardianAuthorization(cfg.DataDir)
	if authorizationErr != nil {
		run.AuthorizationErr = authorizationErr
	} else if !exists {
		run.AuthorizationErr = fmt.Errorf("protected hook guardian authorization is missing")
	} else if !authorization.OK || authorization.FailureCount != 0 ||
		authorization.SuccessCount != authorization.TargetCount {
		run.AuthorizationErr = fmt.Errorf("protected hook guardian authorization is incomplete (%d/%d targets succeeded)", authorization.SuccessCount, authorization.TargetCount)
	} else if freshnessErr := managed.ValidateHookGuardianFreshness(authorization.UpdatedAt, time.Now()); freshnessErr != nil {
		run.AuthorizationErr = fmt.Errorf("protected hook guardian authorization is not fresh: %w", freshnessErr)
	}
	apiAddr := strings.TrimSpace(enterpriseHookAPIAddr)
	if apiAddr == "" {
		apiAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Gateway.APIPort)
	}
	proxyAddr := strings.TrimSpace(enterpriseHookProxyAddr)
	if proxyAddr == "" {
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Guardrail.Port)
	}
	if err := verifyEnterpriseHookManagedEnrollments(manifest, apiAddr); err != nil {
		if run.AuthorizationErr == nil {
			run.AuthorizationErr = fmt.Errorf("protected enrollment set is not exact: %w", err)
		} else {
			run.AuthorizationErr = fmt.Errorf(
				"%v; protected enrollment set is not exact: %w",
				run.AuthorizationErr,
				err,
			)
		}
	}
	registry := newEnterpriseHooksConnectorRegistry()
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		row := enterpriseHookReconcileRow{
			User:      strings.TrimSpace(target.User),
			UserHome:  strings.TrimSpace(target.UserHome),
			SID:       strings.TrimSpace(target.SID),
			Connector: strings.TrimSpace(target.Connector),
		}
		resolved, targetErr := resolveEnterpriseHookTargetValues(target.User, target.UserHome, intPtrValue(target.UID), intPtrValue(target.GID), target.SID, target.DataDir)
		if targetErr == nil && target.SID != "" {
			resolved.sid = strings.TrimSpace(target.SID)
		}
		if targetErr == nil {
			row.SID = resolved.sid
			row.UserHome = resolved.home
		}
		token := ""
		otlpToken := ""
		if targetErr == nil {
			token, targetErr = loadEnterpriseHookScopedToken(cfg.DataDir, target.Connector)
		}
		if targetErr == nil {
			otlpToken, targetErr = loadEnterpriseHookScopedOTLPToken(cfg.DataDir, target.Connector)
		}
		if targetErr == nil {
			opts := enterprisehooks.InstallOptions{
				ConnectorName: target.Connector,
				UserHome:      resolved.home,
				OwnerUID:      resolved.uid,
				OwnerGID:      resolved.gid,
				OwnerSID:      resolved.sid,
				DataDir:       strings.TrimSpace(target.DataDir),
				APIAddr:       apiAddr,
				ProxyAddr:     proxyAddr,
				APIToken:      token,
				OTLPPathToken: otlpToken,
				HookFailMode:  cfg.EffectiveHookFailModeForConnector(target.Connector),
				GuardrailMode: cfg.EffectiveGuardrailModeForConnector(target.Connector),
				HILTEnabled:   cfg.EffectiveHILTForConnector(target.Connector).Enabled,
				AgentVersion:  strings.TrimSpace(target.AgentVersion),
				WorkspaceDir:  cfg.ConnectorWorkspaceDir(),
				Registry:      registry,
			}
			var result enterprisehooks.InstallResult
			result, targetErr = enterprisehooks.Verify(ctx, opts)
			if targetErr == nil {
				row.Result = &result
				row.UserHome = result.UserHome
				row.Connector = result.Connector
				row.OK = true
			}
		}
		if targetErr == nil && exists {
			covered := false
			for _, protected := range authorization.ProtectedTargets {
				if enterpriseHookRowMatches(protected, row.User, row.UserHome, row.SID, strings.ToLower(strings.TrimSpace(row.Connector))) {
					covered = true
					break
				}
			}
			if !covered {
				targetErr = fmt.Errorf("protected authorization does not cover target")
			}
		}
		if targetErr != nil {
			row.OK = false
			row.Error = targetErr.Error()
			run.Failures++
		}
		run.Rows = append(run.Rows, row)
	}
	if run.AuthorizationErr == nil && exists {
		if issues := compareEnterpriseHookProtectedTargetSets(run.Rows, authorization.ProtectedTargets); len(issues) > 0 {
			run.AuthorizationErr = fmt.Errorf("%s", strings.Join(issues, "; "))
		}
	}
	return run, nil
}

func runEnterpriseHookReconcileOnce(ctx context.Context) (enterpriseHookReconcileRun, error) {
	run := enterpriseHookReconcileRun{Manifest: enterpriseHookManifest}
	if cfg == nil {
		return run, fmt.Errorf("enterprise hooks reconcile: config is not loaded")
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return run, err
	}
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if err := managed.ValidateTrustedFilePath(enterpriseHookManifest, "hook guardian manifest"); err != nil {
			return run, fmt.Errorf("enterprise hooks reconcile: manifest trust check failed: %w", err)
		}
		if err := validateEnterpriseHookManagedRuntime(); err != nil {
			return run, err
		}
	}
	manifest, err := enterprisehooks.LoadManifest(enterpriseHookManifest)
	if err != nil {
		return run, err
	}
	apiAddr := strings.TrimSpace(enterpriseHookAPIAddr)
	if apiAddr == "" {
		apiAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Gateway.APIPort)
	}
	proxyAddr := strings.TrimSpace(enterpriseHookProxyAddr)
	if proxyAddr == "" {
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Guardrail.Port)
	}
	// Revoke removed/disabled SIDs before touching any target runtime. This
	// makes stale enrollment fail closed even when a later repair fails.
	if err := syncEnterpriseHookManagedEnrollments(manifest, apiAddr, false); err != nil {
		return run, fmt.Errorf(
			"enterprise hooks reconcile: revoke stale protected enrollments: %w",
			err,
		)
	}
	registry := newEnterpriseHooksConnectorRegistry()

	rows := make([]enterpriseHookReconcileRow, 0, len(manifest.Targets))
	failures := 0
	watchDirs := map[string]struct{}{}
	exclusiveFiles := map[string]struct{}{}
	sharedFiles := map[string]struct{}{}
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		row := enterpriseHookReconcileRow{
			User:      strings.TrimSpace(target.User),
			UserHome:  strings.TrimSpace(target.UserHome),
			SID:       strings.TrimSpace(target.SID),
			Connector: strings.TrimSpace(target.Connector),
		}
		token := ""
		otlpToken := ""
		resolved, err := resolveEnterpriseHookTargetValues(target.User, target.UserHome, intPtrValue(target.UID), intPtrValue(target.GID), target.SID, target.DataDir)
		if err == nil {
			row.SID = strings.TrimSpace(resolved.sid)
		}
		if err == nil {
			var tokenErr error
			token, tokenErr = enterpriseHookScopedTokenMinter(cfg.DataDir, target.Connector)
			if tokenErr != nil {
				err = tokenErr
			}
		}
		if err == nil {
			var tokenErr error
			otlpToken, tokenErr = enterpriseHookScopedOTLPTokenMinter(cfg.DataDir, target.Connector)
			if tokenErr != nil {
				err = tokenErr
			}
		}
		if err == nil {
			previousProtection, authorizationErr := previousEnterpriseHookProtection(
				cfg.DataDir,
				target.User,
				resolved.home,
				resolved.sid,
				target.Connector,
			)
			if authorizationErr != nil {
				err = authorizationErr
			}
			opts := enterprisehooks.InstallOptions{
				ConnectorName:                      target.Connector,
				UserHome:                           resolved.home,
				OwnerUID:                           resolved.uid,
				OwnerGID:                           resolved.gid,
				OwnerSID:                           resolved.sid,
				DataDir:                            strings.TrimSpace(target.DataDir),
				APIAddr:                            apiAddr,
				ProxyAddr:                          proxyAddr,
				APIToken:                           token,
				OTLPPathToken:                      otlpToken,
				HookFailMode:                       cfg.EffectiveHookFailModeForConnector(target.Connector),
				GuardrailMode:                      cfg.EffectiveGuardrailModeForConnector(target.Connector),
				HILTEnabled:                        cfg.EffectiveHILTForConnector(target.Connector).Enabled,
				AgentVersion:                       strings.TrimSpace(target.AgentVersion),
				WorkspaceDir:                       cfg.ConnectorWorkspaceDir(),
				Registry:                           registry,
				AllowMissingHookConfigRepair:       previousProtection.PreviouslyProtected,
				RecoveryHookContractLockUpdatedAt:  previousProtection.HookContractLockUpdatedAt,
				RecoveryHookContractEntryUpdatedAt: previousProtection.HookContractEntryUpdatedAt,
			}
			if err == nil {
				if dirs, watchErr := enterprisehooks.WatchDirs(opts); watchErr == nil {
					for _, dir := range dirs {
						watchDirs[dir] = struct{}{}
					}
				}
			}
			if own, filesErr := enterprisehooks.WatchOwnedFiles(opts); filesErr == nil {
				for _, f := range own.ExclusiveWriter {
					exclusiveFiles[f] = struct{}{}
				}
				for _, f := range own.SharedWriter {
					sharedFiles[f] = struct{}{}
				}
			}
			if err == nil {
				var result enterprisehooks.InstallResult
				result, err = enterprisehooks.Install(ctx, opts)
				if err == nil {
					row.OK = true
					row.UserHome = result.UserHome
					row.Connector = result.Connector
					row.Result = &result
				}
			}
		}
		if err != nil {
			failures++
			row.OK = false
			row.Error = err.Error()
		}
		rows = append(rows, row)
	}

	var enrollmentErr error
	if failures == 0 {
		enrollmentErr = syncEnterpriseHookManagedEnrollments(manifest, apiAddr, true)
	}
	stateErr := writeEnterpriseHookGuardianState(cfg.DataDir, enterpriseHookManifest, rows, failures)
	if stateErr == nil && enrollmentErr != nil {
		stateErr = fmt.Errorf(
			"publish exact protected enrollment set: %w",
			enrollmentErr,
		)
	}
	run.Rows = rows
	run.Failures = failures
	run.StateErr = stateErr
	run.WatchDirs = sortedEnterpriseHookWatchDirs(watchDirs)
	run.WatchExclusiveFiles = sortedEnterpriseHookWatchDirs(exclusiveFiles)
	run.WatchSharedFiles = sortedEnterpriseHookWatchDirs(sharedFiles)
	return run, nil
}

func runEnterpriseHooksWatch(cmd *cobra.Command, _ []string) error {
	if cfg == nil {
		return fmt.Errorf("enterprise hooks watch: config is not loaded")
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return err
	}
	if enterpriseHookWatchInterval <= 0 {
		return fmt.Errorf("enterprise hooks watch: --interval must be positive")
	}
	if enterpriseHookWatchDebounce <= 0 {
		return fmt.Errorf("enterprise hooks watch: --debounce must be positive")
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("enterprise hooks watch: create fsnotify watcher: %w", err)
	}
	defer fsw.Close()

	watched := map[string]struct{}{}
	// Owned-file allowlists, split by expected writer. fsnotify on
	// macOS reports events at directory granularity — watching
	// ~/.codex/ to see config.toml also sees every session log,
	// sqlite WAL rotation, and history append the agent itself
	// performs. We split further because the "owned" file itself may
	// be written by the agent too (Codex rewrites its own config.toml
	// constantly). See WatchOwnership doc for the reaction policy per
	// class; both maps are rebuilt from the run's WatchExclusiveFiles
	// / WatchSharedFiles after each reconcile.
	exclusiveOwned := map[string]struct{}{} // DC-only writers — any event triggers
	sharedOwned := map[string]struct{}{}    // agent + DC writers — Create/Remove/Rename trigger
	// Post-reconcile guards against the self-trigger loop. Every
	// reconcile writes into watched dirs (chmod on hook configs and
	// hook scripts inside hardenInstallFootprint, plus writing
	// hook_guardian_state.json / protected_targets.json). Those writes
	// fire fsnotify events on the dirs we watch, which — with no guard
	// — schedule another reconcile ~750 ms later, whose writes fire
	// more events, forever.
	//
	// Two layered defences:
	//
	//   settleUntil    - short (default 2 s) window that suppresses
	//                    Write/Chmod events observed immediately
	//                    after a reconcile completes; the vast
	//                    majority of self-writes land here.
	//
	//   lastRowsHash   - SHA-256 of the reconcile row set. After each
	//                    reconcile we compare against the previous
	//                    hash; when unchanged we log a single
	//                    reason=fsnotify_no_change line and skip
	//                    re-arming the debounce timer even if events
	//                    kept leaking past settleUntil (macOS
	//                    FSEvents can batch chmod events with several
	//                    seconds of latency, which is longer than any
	//                    reasonable settle window). This breaks the
	//                    tail-chasing loop even under adverse fs
	//                    event timing.
	settleUntil := time.Time{}
	droppedInSettle := 0
	var lastRowsHash string
	// Track the fsnotify event that most recently armed the debounce.
	// Included in the next reconcile log line so a `no_change=true`
	// churn can be traced to the specific file+op that keeps firing.
	// Cleared on every reconcile (fsnotify OR interval).
	var lastTriggerPath string
	var lastTriggerOp fsnotify.Op
	repairRetryNeeded := false
	repairRetryDelay := time.Duration(0)
	reconcile := func(reason string) (bool, error) {
		run, err := runEnterpriseHookReconcileOnce(cmd.Context())
		if err != nil {
			repairRetryNeeded = true
			return false, err
		}
		dirs := append([]string{filepath.Dir(filepath.Clean(enterpriseHookManifest))}, run.WatchDirs...)
		if err := syncEnterpriseHookWatchDirs(fsw, watched, dirs); err != nil {
			// Match the runEnterpriseHookReconcileOnce error path: mark
			// retry so the caller schedules a backoff attempt rather than
			// waiting for the periodic interval to recover.
			repairRetryNeeded = true
			return false, fmt.Errorf("enterprise hooks watch: synchronize watch directories: %w", err)
		}
		// Rebuild the owned-file allowlists from this run. The
		// manifest itself is treated as exclusive-writer: only the
		// installer / operator ever edits it, so any change is a real
		// signal (new user added, connector disabled).
		for k := range exclusiveOwned {
			delete(exclusiveOwned, k)
		}
		for k := range sharedOwned {
			delete(sharedOwned, k)
		}
		exclusiveOwned[filepath.Clean(enterpriseHookManifest)] = struct{}{}
		for _, f := range run.WatchExclusiveFiles {
			exclusiveOwned[filepath.Clean(f)] = struct{}{}
		}
		for _, f := range run.WatchSharedFiles {
			sharedOwned[filepath.Clean(f)] = struct{}{}
		}
		status := "ok"
		if run.Failures > 0 || run.StateErr != nil {
			status = "attention"
		}
		rowsHash := enterpriseHookReconcileRowsHash(run.Rows)
		changed := rowsHash != lastRowsHash
		lastRowsHash = rowsHash
		triggerTag := ""
		if reason == "fsnotify" && lastTriggerPath != "" {
			// Attribute the reconcile to the specific fsnotify event
			// that armed the debounce. When a `no_change=true` cycle
			// keeps recurring, this reveals which path is generating
			// the noise so it can be reclassified or filtered.
			triggerTag = fmt.Sprintf(" trigger_path=%q trigger_op=%s", lastTriggerPath, lastTriggerOp)
		}
		if changed {
			fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] reconcile reason=%s status=%s targets=%d failures=%d watch_dirs=%d%s\n", reason, status, len(run.Rows), run.Failures, len(watched), triggerTag)
		} else {
			// Log at DEBUG-ish cadence: one line per no-change
			// reconcile is fine and load-bearing for triage (we still
			// want to know the guardian is alive), but keep it
			// distinguishable from a real repair.
			fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] reconcile reason=%s status=%s targets=%d failures=%d watch_dirs=%d no_change=true%s\n", reason, status, len(run.Rows), run.Failures, len(watched), triggerTag)
		}
		lastTriggerPath = ""
		lastTriggerOp = 0
		if run.StateErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] state write failed: %s\n", run.StateErr)
		}
		repairRetryNeeded = run.Failures > 0 || run.StateErr != nil
		if !repairRetryNeeded {
			repairRetryDelay = 0
		}
		// When the row set is byte-identical to the previous run,
		// any Write/Chmod events still leaking past the normal
		// settle window are tail-writes from our own reconcile
		// (macOS FSEvents can batch chmod with 3-5 s latency).
		// Widen the settle window modestly — enough to cover
		// FSEvents batching, NOT enough to swallow a real subsequent
		// tamper. Cap at 3x settle so the widened window stays in
		// seconds, not minutes. Create/Remove/Rename events are exempt
		// from suppression by enterpriseHookWatchEventInSettleWindow,
		// so widening the window here does not risk missing a user
		// replacement or deletion even if the previous reconcile
		// classified as no_change.
		settle := enterpriseHookWatchSettle
		if !changed {
			settle = enterpriseHookWatchSettle * 3
		}
		settleUntil = time.Now().Add(settle)
		droppedInSettle = 0
		return changed, nil
	}

	// Spec 003 B3: in managed_enterprise mode, tolerate a missing
	// targets.yaml at startup by fsnotify-waiting for UCB to drop it.
	// Non-managed-enterprise deployments retain the existing hard-exit
	// behaviour (an operator explicitly asked for a manifest that
	// isn't there; loudly refusing is the right thing).
	if _, err := reconcile("startup"); err != nil {
		if !isMissingManifestErr(err) || cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
			return err
		}
		if waitErr := waitForEnterpriseHookManifestManaged(cmd.Context(), cmd.ErrOrStderr(), fsw); waitErr != nil {
			return waitErr
		}
		// Manifest is present now — re-run the startup reconcile so
		// the watch loop enters its main select with a valid row set,
		// hashes, and watched dirs. Any other error from THIS retry
		// (parse failure, missing file races back to gone, etc.) is
		// fatal — we've done our one bounded wait; further retries
		// belong to the SCM restart cycle.
		if _, err := reconcile("startup_after_wait"); err != nil {
			return err
		}
	}
	// Successful startup reconcile ⇒ manifest is loaded ⇒ publish
	// the guardian-side "ready" state so the sidecar's health surface
	// (spec 003 REQ-19) can collapse to overall `ready`.
	writeGuardianStateOrLog(cmd.ErrOrStderr(), guardianstate.StateReady)

	ticker := time.NewTicker(enterpriseHookWatchInterval)
	defer ticker.Stop()
	debounce := time.NewTimer(time.Hour)
	if !debounce.Stop() {
		<-debounce.C
	}
	debouncePending := false
	debounceReason := ""
	repairRetry := time.NewTimer(time.Hour)
	if !repairRetry.Stop() {
		<-repairRetry.C
	}
	defer repairRetry.Stop()
	repairRetryPending := false
	// Keep failed-repair backoff independent from filesystem debounce. A
	// target that can generate owned-file events must not be able to postpone
	// the retry that replaces a released locked or oversized artifact.
	scheduleRepairRetry := func() {
		if !repairRetryNeeded || repairRetryPending {
			return
		}
		repairRetryDelay = enterpriseHookWatchNextRepairRetryDelay(repairRetryDelay)
		resetEnterpriseHookWatchTimer(repairRetry, repairRetryDelay)
		repairRetryPending = true
		fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] repair incomplete; retrying in %s\n", repairRetryDelay)
	}
	cancelRepairRetry := func() {
		if !repairRetryPending {
			return
		}
		if !repairRetry.Stop() {
			select {
			case <-repairRetry.C:
			default:
			}
		}
		repairRetryPending = false
	}
	cancelPendingDebounce := func() {
		if !debouncePending {
			return
		}
		if !debounce.Stop() {
			select {
			case <-debounce.C:
			default:
			}
		}
		debouncePending = false
		debounceReason = ""
	}
	scheduleRepairRetry()

	for {
		select {
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		case event, ok := <-fsw.Events:
			if !ok {
				if err := cmd.Context().Err(); err != nil {
					return err
				}
				return errors.New("enterprise hooks watch: fsnotify event channel closed unexpectedly")
			}
			if !enterpriseHookWatchEventRelevant(event) {
				continue
			}
			// Only react to events on paths DefenseClaw itself owns.
			// Two policies apply depending on who writes to the file:
			//
			//   * ExclusiveWriter (hook scripts, .token sidecars,
			//     _hardening.sh, backup files, the manifest): only DC
			//     writes here, so any event is meaningful.
			//   * SharedWriter (the native agent config —
			//     ~/.codex/config.toml, ~/.claude/settings.json,
			//     ~/.cursor/hooks.json): the agent itself constantly
			//     rewrites these during normal use. Create, Remove,
			//     and Rename are real tamper signals; Write and Chmod
			//     are the agent doing its own thing
			//     and the 5-min backstop handles any in-place stripping.
			//
			// Events on unowned paths (agent session state, sqlite
			// WAL churn, cache writes, workspace snapshots) are
			// silently dropped — no log, no debounce — because they
			// happen continuously and previously dominated the log.
			//
			// Empty maps means we haven't run a reconcile yet (only
			// possible pre-startup); fall through so the startup
			// reconcile flow is unaffected.
			if !enterpriseHookWatchOwnedEventActionable(event, exclusiveOwned, sharedOwned) {
				continue
			}
			// Drop Write/Chmod events observed inside the
			// post-reconcile settle window: they are almost certainly
			// the tail of writes the reconcile itself just made.
			// Create/Remove/Rename must still reconcile because a
			// user can atomically replace a protected path inside the
			// settle window, leaving the destination present just like
			// the guardian's own atomic rename tail.
			if enterpriseHookWatchEventInSettleWindow(time.Now(), settleUntil, event.Op) {
				droppedInSettle++
				continue
			}
			// Log once when the first non-suppressed event lands after
			// a settle window closed — helps operators tell "user
			// tampered" from "guardian saw its own tail" during
			// triage.
			if droppedInSettle > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] settled: suppressed %d self-write event(s) within %s of last reconcile\n", droppedInSettle, enterpriseHookWatchSettle)
				droppedInSettle = 0
			}
			// Record which specific event armed the debounce so the
			// resulting reconcile log line names the culprit path.
			// Preserve the FIRST event of a burst rather than
			// overwriting; that's the one that actually caused the
			// debounce arm, subsequent events during the 750ms window
			// are already-scheduled noise.
			if lastTriggerPath == "" {
				lastTriggerPath = filepath.Clean(event.Name)
				lastTriggerOp = event.Op
			}
			resetEnterpriseHookWatchTimer(debounce, enterpriseHookWatchDebounce)
			debouncePending = true
			debounceReason = "fsnotify"
		case err, ok := <-fsw.Errors:
			if !ok {
				if contextErr := cmd.Context().Err(); contextErr != nil {
					return contextErr
				}
				return errors.New("enterprise hooks watch: fsnotify error channel closed unexpectedly")
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] fsnotify error: %s\n", err)
		case <-debounce.C:
			if debouncePending {
				debouncePending = false
				reason := debounceReason
				debounceReason = ""
				if reason == "" {
					reason = "fsnotify"
				}
				if _, err := reconcile(reason); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] reconcile after %s failed: %s\n", reason, err)
				}
				if repairRetryNeeded {
					scheduleRepairRetry()
				} else {
					cancelRepairRetry()
				}
			}
		case <-repairRetry.C:
			repairRetryPending = false
			if _, err := reconcile("retry"); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] reconcile after retry failed: %s\n", err)
			}
			if repairRetryNeeded {
				scheduleRepairRetry()
			} else {
				cancelRepairRetry()
			}
		case <-ticker.C:
			if _, err := reconcile("interval"); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] interval reconcile failed: %s\n", err)
			}
			if repairRetryNeeded {
				scheduleRepairRetry()
			} else {
				cancelRepairRetry()
				cancelPendingDebounce()
			}
		}
	}
}

// isMissingManifestErr classifies an error from
// runEnterpriseHookReconcileOnce (which ultimately calls
// enterprisehooks.LoadManifest) as the specific "targets.yaml is not on
// disk yet" case, distinct from parse errors, permission errors, or
// symlink refusals. Only file-not-found is safe to interpret as
// "waiting for UCB to drop the manifest" — everything else is a real
// failure that should surface loudly.
//
// LoadManifest wraps the underlying os.Lstat / os.Open error with
// %w, so errors.Is against os.ErrNotExist reaches the sentinel.
func isMissingManifestErr(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

// writeGuardianStateOrLog writes the guardian's out-of-band state file
// via the guardianstate package and logs a warning on failure. Never
// returns an error: a state-file write failure is a health-surface
// degradation (the sidecar will fall through to its safe default), not
// a reason to fail the guardian's core reconcile path.
func writeGuardianStateOrLog(w io.Writer, state string) {
	if enterpriseHookManifest == "" {
		return
	}
	statePath := guardianstate.PathForStateRoot(filepath.Dir(filepath.Clean(enterpriseHookManifest)))
	if err := guardianstate.WriteState(statePath, state); err != nil {
		fmt.Fprintf(w, "[hook-guardian] warn: could not write %s state file %s: %v\n", state, statePath, err)
	}
}

// waitForEnterpriseHookManifestManaged is the spec 003 B3 bounded wait
// loop. Called only from managed_enterprise + missing-manifest at
// startup. Uses the caller's already-created fsnotify.Watcher so we
// share the same file-descriptor budget the normal watch loop uses;
// on entry the watcher is empty (the reconcile that just failed never
// added dirs). On successful return the watcher is again empty — the
// caller re-runs `reconcile("startup_after_wait")` which re-adds
// dirs based on the freshly-loaded row set.
//
// Behaviour:
//
//   - Writes guardianstate `.state=waiting_for_targets` so the sidecar
//     collapsing rule reports overall `waiting_for_targets` (spec 003
//     REQ-15).
//   - Adds an fsnotify watch on the manifest's parent directory.
//   - Loop: wait for a WRITE/CREATE event on the manifest path OR the
//     poll ticker fires; on either, re-attempt LoadManifest. Success
//     ⇒ return nil (caller resumes normal boot). Missing ⇒ keep
//     waiting.
//   - Hard cap at enterpriseHookTargetsWaitTimeout — return a
//     distinguishable error so the SCM restart cycle picks the
//     guardian back up cleanly (spec 003 AC-06 analogue on the
//     guardian side, though the primary AC-06 is for the daemon).
//
// A non-missing error from a retried LoadManifest (parse failure,
// symlink) is treated as fatal: we did our one bounded wait, an
// operator now dropped a bad file, further recovery belongs to a
// human triage rather than an unbounded wait loop.
func waitForEnterpriseHookManifestManaged(ctx context.Context, w io.Writer, fsw *fsnotify.Watcher) error {
	manifestPath := filepath.Clean(enterpriseHookManifest)
	parentDir := filepath.Dir(manifestPath)

	fmt.Fprintf(w, "[hook-guardian] managed-enterprise: targets.yaml missing at %s, waiting on fsnotify (parent=%s)\n", manifestPath, parentDir)
	writeGuardianStateOrLog(w, guardianstate.StateWaitingForTargets)

	if err := fsw.Add(parentDir); err != nil {
		return fmt.Errorf("enterprise hooks watch: add wait dir %s: %w", parentDir, err)
	}
	// Best-effort cleanup: remove the watch when we return so the
	// caller's fresh startup_after_wait reconcile gets a clean
	// watched-set to sync against. A Remove error is not fatal —
	// syncEnterpriseHookWatchDirs will fix any drift on the next
	// reconcile.
	defer func() { _ = fsw.Remove(parentDir) }()

	// Poll at a fixed interval so a missed fsnotify event (Windows
	// can drop events under load, and network shares may not emit
	// them at all) does not extend the wait beyond one poll interval.
	poll := time.NewTicker(enterpriseHookTargetsWaitPoll)
	defer poll.Stop()

	// Hard cap so a broken UCB pipeline does not leave the guardian
	// silently waiting forever. Distinguishable exit — see spec 003
	// AC-06's daemon-side counterpart.
	deadline, cancel := context.WithTimeout(ctx, enterpriseHookTargetsWaitTimeout)
	defer cancel()

	// Try LoadManifest once up front — the manifest may have landed
	// between the failing startup reconcile and this fsnotify.Add
	// call. Without this probe we'd sit for enterpriseHookTargetsWaitPoll
	// waiting for an event that already happened.
	if err := probeManifestPresent(manifestPath); err == nil {
		fmt.Fprintf(w, "[hook-guardian] targets.yaml present on entry to wait loop; resuming\n")
		return nil
	}

	for {
		select {
		case <-deadline.Done():
			// Distinguish timeout from ctx.Done: the operator's ctx
			// is fine, only our bounded wait ran out.
			if errors.Is(deadline.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("enterprise hooks watch: targets.yaml wait timeout after %s at %s — exiting for SCM restart", enterpriseHookTargetsWaitTimeout, manifestPath)
			}
			return deadline.Err()
		case event := <-fsw.Events:
			// Only react to writes/creates for the target file; ignore
			// noise for siblings (a stray temp file, chmod on the
			// dir itself).
			if filepath.Clean(event.Name) != manifestPath {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			if err := probeManifestPresent(manifestPath); err == nil {
				fmt.Fprintf(w, "[hook-guardian] targets.yaml appeared (%s); resuming\n", event.Op)
				return nil
			}
		case fswErr := <-fsw.Errors:
			// fsnotify.Errors is documented to deliver only
			// recoverable errors (queue overflow, watcher-internal
			// signals). Log and keep waiting; the ticker will retry.
			if fswErr != nil {
				fmt.Fprintf(w, "[hook-guardian] fsnotify wait error: %v\n", fswErr)
			}
		case <-poll.C:
			if err := probeManifestPresent(manifestPath); err == nil {
				fmt.Fprintf(w, "[hook-guardian] targets.yaml present on poll; resuming\n")
				return nil
			}
		}
	}
}

// probeManifestPresent returns nil if enterprisehooks.LoadManifest can
// open + parse the manifest at path, or the underlying error otherwise.
// Missing-file returns an error that satisfies isMissingManifestErr;
// any other error (parse, symlink, oversized) also returns and is
// escalated by the caller as a fatal condition.
func probeManifestPresent(path string) error {
	_, err := enterprisehooks.LoadManifest(path)
	return err
}

func enterpriseHookWatchNextRepairRetryDelay(previous time.Duration) time.Duration {
	if previous < enterpriseHookWatchRepairRetryMin {
		return enterpriseHookWatchRepairRetryMin
	}
	if previous >= enterpriseHookWatchRepairRetryMax/2 {
		return enterpriseHookWatchRepairRetryMax
	}
	return previous * 2
}

// enterpriseHookWatchEventInSettleWindow reports whether an fsnotify
// event observed at now should be suppressed because it lands inside
// the post-reconcile settle window. A zero settleUntil (never
// reconciled yet, or explicitly disabled) always returns false: never
// suppress.
//
// Only Write/Chmod events are suppressed inside the window. Create,
// Remove, and Rename events remain actionable because a user-owned
// protected file can be atomically replaced immediately after a
// guardian reconcile; checking that the path still exists cannot
// distinguish that tamper from the guardian's own rename tail.
func enterpriseHookWatchEventInSettleWindow(now, settleUntil time.Time, op fsnotify.Op) bool {
	if settleUntil.IsZero() {
		return false
	}
	if op&(fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
		return false
	}
	return now.Before(settleUntil)
}

// enterpriseHookReconcileRowsHash is a content fingerprint over the
// stable subset of a reconcile row set. It is used by the watch loop
// to distinguish a "nothing actually changed" tick (guardian saw its
// own tail) from a real repair (user tampered with a file). Only the
// fields that describe the target's identity and outcome are hashed;
// volatile Result payload internals are intentionally excluded so
// benign per-run details (timestamps, transient path lookups) do not
// flip the hash.
func enterpriseHookReconcileRowsHash(rows []enterpriseHookReconcileRow) string {
	if len(rows) == 0 {
		return "0"
	}
	type hashRow struct {
		User      string `json:"u"`
		UserHome  string `json:"h"`
		Connector string `json:"c"`
		OK        bool   `json:"o"`
		Error     string `json:"e,omitempty"`
	}
	stable := make([]hashRow, 0, len(rows))
	for _, r := range rows {
		stable = append(stable, hashRow{
			User:      r.User,
			UserHome:  r.UserHome,
			Connector: r.Connector,
			OK:        r.OK,
			Error:     r.Error,
		})
	}
	sort.Slice(stable, func(i, j int) bool {
		if stable[i].Connector != stable[j].Connector {
			return stable[i].Connector < stable[j].Connector
		}
		return stable[i].User < stable[j].User
	})
	data, err := json.Marshal(stable)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func enterpriseHooksManagedMutationPreflight() error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	return enterpriseHooksMutationIdentityPreflight()
}

func enterpriseHookWatchEventRelevant(event fsnotify.Event) bool {
	if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove|fsnotify.Chmod) == 0 {
		return false
	}
	return !strings.HasSuffix(filepath.Base(event.Name), ".lock")
}

// enterpriseHookWatchOwnedEventActionable applies the expected-writer
// policy after the broad fsnotify relevance check. Exclusive-writer
// files react to every relevant event. Shared-writer files retain
// suppression for ordinary agent Write/Chmod noise, while Create,
// Remove, and Rename remain actionable so atomic replacement events
// reach the settle classifier. Empty ownership maps preserve the
// pre-startup fallback.
func enterpriseHookWatchOwnedEventActionable(event fsnotify.Event, exclusiveOwned, sharedOwned map[string]struct{}) bool {
	if len(exclusiveOwned) == 0 && len(sharedOwned) == 0 {
		return true
	}
	cleaned := filepath.Clean(event.Name)
	if _, ok := exclusiveOwned[cleaned]; ok {
		return true
	}
	if _, ok := sharedOwned[cleaned]; !ok {
		return false
	}
	return event.Op&(fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0
}

func syncEnterpriseHookWatchDirs(fsw *fsnotify.Watcher, watched map[string]struct{}, dirs []string) error {
	next := map[string]struct{}{}
	var addErrors []error
	for _, dir := range sortedEnterpriseHookStrings(dirs) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		dir = filepath.Clean(dir)
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		next[dir] = struct{}{}
		if _, ok := watched[dir]; ok {
			continue
		}
		if err := fsw.Add(dir); err != nil {
			addErrors = append(addErrors, fmt.Errorf("watch %s: %w", dir, err))
			delete(next, dir)
			continue
		}
	}
	for dir := range watched {
		if _, ok := next[dir]; ok {
			continue
		}
		_ = fsw.Remove(dir)
	}
	for dir := range watched {
		delete(watched, dir)
	}
	for dir := range next {
		watched[dir] = struct{}{}
	}
	return errors.Join(addErrors...)
}

func resetEnterpriseHookWatchTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

func sortedEnterpriseHookWatchDirs(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	return sortedEnterpriseHookStrings(out)
}

func sortedEnterpriseHookStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func validateEnterpriseHookManagedRuntime() error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	if err := managed.ValidateTrustedServiceRuntimeDir(
		cfg.DataDir,
		"hook guardian state data_dir",
		os.Getenv(managed.WindowsServiceAccountEnv),
	); err != nil {
		return fmt.Errorf("enterprise hooks: data_dir trust check failed: %w", err)
	}
	if err := managed.ValidateTrustedRuntimeDir(managed.HookGuardianAuthorizationDir(cfg.DataDir), "hook guardian authorization directory"); err != nil {
		return fmt.Errorf("enterprise hooks: authorization directory trust check failed: %w", err)
	}
	return nil
}

type enterpriseHookGuardianState struct {
	Version          int                          `json:"version"`
	UpdatedAt        string                       `json:"updated_at"`
	Manifest         string                       `json:"manifest"`
	OK               bool                         `json:"ok"`
	TargetCount      int                          `json:"target_count"`
	SuccessCount     int                          `json:"success_count"`
	FailureCount     int                          `json:"failure_count"`
	Results          []enterpriseHookReconcileRow `json:"results"`
	ProtectedTargets []enterpriseHookReconcileRow `json:"protected_targets,omitempty"`
}

type enterpriseHookGuardianAuthorization struct {
	Version          int                          `json:"version"`
	UpdatedAt        string                       `json:"updated_at"`
	OK               bool                         `json:"ok"`
	TargetCount      int                          `json:"target_count"`
	SuccessCount     int                          `json:"success_count"`
	FailureCount     int                          `json:"failure_count"`
	ProtectedTargets []enterpriseHookReconcileRow `json:"protected_targets"`
}

func writeEnterpriseHookGuardianState(dataDir, manifest string, rows []enterpriseHookReconcileRow, failures int) error {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return fmt.Errorf("no data directory configured")
	}
	successes := 0
	for _, row := range rows {
		if row.OK {
			successes++
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	previous, _, err := loadEnterpriseHookGuardianAuthorization(dataDir)
	if err != nil {
		return err
	}
	protected := mergeProtectedEnterpriseHookTargets(previous.ProtectedTargets, rows)
	authorization := enterpriseHookGuardianAuthorization{
		Version:          1,
		UpdatedAt:        now,
		OK:               failures == 0 && successes == len(rows),
		TargetCount:      len(rows),
		SuccessCount:     successes,
		FailureCount:     failures,
		ProtectedTargets: protected,
	}
	authorizationData, err := json.MarshalIndent(authorization, "", "  ")
	if err != nil {
		return err
	}
	authorizationData = append(authorizationData, '\n')
	authorizationDir := managed.HookGuardianAuthorizationDir(dataDir)
	if info, statErr := os.Lstat(authorizationDir); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("hook guardian authorization path is not a trusted directory: %s", authorizationDir)
		}
		if err := enterpriseHookAuthorizationDirTrustCheck(authorizationDir); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect hook guardian authorization directory: %w", statErr)
	}
	if err := os.MkdirAll(authorizationDir, 0o750); err != nil {
		return fmt.Errorf("create hook guardian authorization directory: %w", err)
	}
	if err := os.Chmod(authorizationDir, 0o750); err != nil {
		return fmt.Errorf("harden hook guardian authorization directory: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(authorizationDir); err != nil {
		return fmt.Errorf("set hook guardian authorization directory ownership: %w", err)
	}
	if err := enterpriseHookAuthorizationDirTrustCheck(authorizationDir); err != nil {
		return err
	}
	authorizationPath := filepath.Join(authorizationDir, hookGuardianAuthorizationFile)
	if err := writeEnterpriseHookProtectedFile(authorizationPath, authorizationData); err != nil {
		return fmt.Errorf("write %s: %w", authorizationPath, err)
	}
	if err := os.Chmod(authorizationPath, 0o640); err != nil {
		return fmt.Errorf("make hook guardian authorization readable: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(authorizationPath); err != nil {
		return fmt.Errorf("set hook guardian authorization file ownership: %w", err)
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(authorizationPath); err != nil {
		return err
	}

	state := enterpriseHookGuardianState{
		Version:      1,
		UpdatedAt:    now,
		Manifest:     strings.TrimSpace(manifest),
		OK:           failures == 0,
		TargetCount:  len(rows),
		SuccessCount: successes,
		FailureCount: failures,
		Results:      rows,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(dataDir, hookGuardianStateFile)
	if err := writeEnterpriseHookProtectedFile(path, data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("make hook guardian state readable: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return fmt.Errorf("set hook guardian state ownership: %w", err)
	}
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if err := managed.ValidateTrustedServiceRuntimeFilePath(
			path,
			"hook guardian state",
			os.Getenv(managed.WindowsServiceAccountEnv),
		); err != nil {
			return err
		}
	}
	return nil
}

type enterpriseHookPreviousProtection struct {
	PreviouslyProtected        bool
	HookContractLockUpdatedAt  string
	HookContractEntryUpdatedAt string
}

func previousEnterpriseHookProtection(
	dataDir,
	userName,
	userHome,
	sid,
	connectorName string,
) (enterpriseHookPreviousProtection, error) {
	var protection enterpriseHookPreviousProtection
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	userName = strings.TrimSpace(userName)
	userHome = filepath.Clean(strings.TrimSpace(userHome))
	sid = strings.TrimSpace(sid)
	if dataDir == "" || connectorName == "" {
		return protection, nil
	}
	authorization, _, err := loadEnterpriseHookGuardianAuthorization(dataDir)
	if err != nil {
		return protection, err
	}
	for _, row := range authorization.ProtectedTargets {
		if !enterpriseHookRowMatches(row, userName, userHome, sid, connectorName) {
			continue
		}
		protection.PreviouslyProtected = true
		if row.Result != nil {
			protection.HookContractLockUpdatedAt =
				strings.TrimSpace(row.Result.HookContractLockUpdatedAt)
			protection.HookContractEntryUpdatedAt =
				strings.TrimSpace(row.Result.HookContractEntryUpdatedAt)
		}
		return protection, nil
	}
	return protection, nil
}

func previousEnterpriseHookSuccess(
	dataDir,
	userName,
	userHome,
	sid,
	connectorName string,
) (bool, error) {
	protection, err := previousEnterpriseHookProtection(
		dataDir,
		userName,
		userHome,
		sid,
		connectorName,
	)
	return protection.PreviouslyProtected, err
}

func loadEnterpriseHookGuardianAuthorization(dataDir string) (enterpriseHookGuardianAuthorization, bool, error) {
	path := managed.HookGuardianAuthorizationPath(dataDir)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return enterpriseHookGuardianAuthorization{}, false, nil
	}
	if err != nil {
		return enterpriseHookGuardianAuthorization{}, false, fmt.Errorf("inspect hook guardian authorization %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return enterpriseHookGuardianAuthorization{}, true, fmt.Errorf("hook guardian authorization is not a regular file: %s", path)
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		return enterpriseHookGuardianAuthorization{}, true, err
	}
	data, err := readEnterpriseHookBoundedFile(
		path,
		info,
		enterpriseHookGuardianAuthorizationMaxBytes,
		"hook guardian authorization",
	)
	if err != nil {
		return enterpriseHookGuardianAuthorization{}, true, fmt.Errorf("read hook guardian authorization %s: %w", path, err)
	}
	var state enterpriseHookGuardianAuthorization
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return enterpriseHookGuardianAuthorization{}, true, fmt.Errorf("parse hook guardian authorization %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return enterpriseHookGuardianAuthorization{}, true, fmt.Errorf("parse hook guardian authorization %s: trailing content", path)
	}
	if state.Version != 1 {
		return enterpriseHookGuardianAuthorization{}, true, fmt.Errorf("hook guardian authorization %s has unsupported version %d", path, state.Version)
	}
	if state.TargetCount < 0 || state.SuccessCount < 0 || state.FailureCount < 0 ||
		state.SuccessCount+state.FailureCount != state.TargetCount {
		return enterpriseHookGuardianAuthorization{}, true, fmt.Errorf("hook guardian authorization %s has inconsistent target counts", path)
	}
	rows := make([]enterpriseHookReconcileRow, 0, len(state.ProtectedTargets))
	seen := map[string]struct{}{}
	for _, row := range state.ProtectedTargets {
		if !row.OK {
			return enterpriseHookGuardianAuthorization{}, true, fmt.Errorf("hook guardian authorization %s contains an unsuccessful protected target", path)
		}
		key := enterpriseHookProtectedTargetKey(row)
		if key == "" {
			return enterpriseHookGuardianAuthorization{}, true, fmt.Errorf("hook guardian authorization %s contains an incomplete protected target", path)
		}
		if _, duplicate := seen[key]; duplicate {
			return enterpriseHookGuardianAuthorization{}, true, fmt.Errorf("hook guardian authorization %s contains duplicate protected target %q", path, key)
		}
		seen[key] = struct{}{}
		rows = append(rows, row)
	}
	state.ProtectedTargets = rows
	return state, true, nil
}

func readEnterpriseHookBoundedFile(
	path string,
	info os.FileInfo,
	maxBytes int64,
	label string,
) ([]byte, error) {
	if info == nil {
		return nil, fmt.Errorf("%s metadata is unavailable", label)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular non-link file", label)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", label, maxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("%s changed identity before open", label)
	}
	if openedInfo.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", label, maxBytes)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(openedInfo, current) {
		return nil, fmt.Errorf("%s changed identity before read", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", label, maxBytes)
	}
	return data, nil
}

func mergeProtectedEnterpriseHookTargets(previous, current []enterpriseHookReconcileRow) []enterpriseHookReconcileRow {
	previousByKey := map[string]enterpriseHookReconcileRow{}
	for _, row := range previous {
		if !row.OK {
			continue
		}
		if key := enterpriseHookProtectedTargetKey(row); key != "" {
			previousByKey[key] = row
		}
	}
	// The current enabled manifest is the authorization allow-list. Preserve a
	// prior successful row only when that same target is still present but its
	// current repair failed; removed or disabled targets must be revoked on the
	// next reconciliation instead of surviving forever in the ledger.
	merged := map[string]enterpriseHookReconcileRow{}
	for _, row := range current {
		key := enterpriseHookProtectedTargetKey(row)
		if key == "" {
			continue
		}
		if row.OK {
			merged[key] = row
			continue
		}
		if prior, ok := previousByKey[key]; ok {
			merged[key] = prior
		}
	}
	out := make([]enterpriseHookReconcileRow, 0, len(merged))
	for _, row := range merged {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		return enterpriseHookProtectedTargetKey(out[i]) < enterpriseHookProtectedTargetKey(out[j])
	})
	return out
}

func enterpriseHookProtectedTargetKey(row enterpriseHookReconcileRow) string {
	connectorName := strings.ToLower(strings.TrimSpace(row.Connector))
	if connectorName == "" && row.Result != nil {
		connectorName = strings.ToLower(strings.TrimSpace(row.Result.Connector))
	}
	if connectorName == "" {
		return ""
	}
	if sid := strings.ToUpper(strings.TrimSpace(row.SID)); sid != "" {
		return connectorName + "\x00sid\x00" + sid
	}
	if userName := strings.TrimSpace(row.User); userName != "" {
		return connectorName + "\x00user\x00" + userName
	}
	home := strings.TrimSpace(row.UserHome)
	if home == "" && row.Result != nil {
		home = row.Result.UserHome
	}
	if home == "" {
		return ""
	}
	return connectorName + "\x00home\x00" + filepath.Clean(home)
}

func enterpriseHookRowMatches(row enterpriseHookReconcileRow, userName, userHome, sid, connectorName string) bool {
	rowConnector := strings.ToLower(strings.TrimSpace(row.Connector))
	if rowConnector == "" && row.Result != nil {
		rowConnector = strings.ToLower(strings.TrimSpace(row.Result.Connector))
	}
	if rowConnector != connectorName {
		return false
	}
	rowSID := strings.TrimSpace(row.SID)
	sid = strings.TrimSpace(sid)
	if rowSID != "" || sid != "" {
		return rowSID != "" && sid != "" && strings.EqualFold(rowSID, sid)
	}
	if userName != "" && strings.TrimSpace(row.User) == userName {
		return true
	}
	rowHome := strings.TrimSpace(row.UserHome)
	if rowHome == "" && row.Result != nil {
		rowHome = row.Result.UserHome
	}
	return userHome != "" && filepath.Clean(rowHome) == userHome
}

type enterpriseHookTarget struct {
	home string
	uid  int
	gid  int
	sid  string
}

func resolveEnterpriseHookTarget() (enterpriseHookTarget, error) {
	return resolveEnterpriseHookTargetValues(enterpriseHookUser, enterpriseHookUserHome, enterpriseHookUID, enterpriseHookGID, enterpriseHookSID, enterpriseHookDataDir)
}

func resolveEnterpriseHookTargetValues(userName, userHome string, uid, gid int, sid, dataDir string) (enterpriseHookTarget, error) {
	target := enterpriseHookTarget{
		home: strings.TrimSpace(userHome),
		uid:  uid,
		gid:  gid,
		sid:  strings.TrimSpace(sid),
	}
	if name := strings.TrimSpace(userName); name != "" &&
		!(runtime.GOOS == "windows" && target.home != "") {
		u, err := user.Lookup(name)
		if err != nil {
			return target, fmt.Errorf("enterprise hooks: lookup user %q: %w", name, err)
		}
		if target.home == "" {
			target.home = u.HomeDir
		}
		if target.uid < 0 {
			if runtime.GOOS == "windows" {
				if target.sid == "" {
					target.sid = strings.TrimSpace(u.Uid)
				}
			} else {
				uid, err := strconv.Atoi(u.Uid)
				if err != nil {
					return target, fmt.Errorf("enterprise hooks: parse uid for %q: %w", name, err)
				}
				target.uid = uid
			}
		}
		if target.gid < 0 {
			if runtime.GOOS != "windows" {
				gid, err := strconv.Atoi(u.Gid)
				if err != nil {
					return target, fmt.Errorf("enterprise hooks: parse gid for %q: %w", name, err)
				}
				target.gid = gid
			}
		}
	}
	if target.home == "" && target.sid != "" {
		home, err := enterpriseHookSIDProfilePath(target.sid)
		if err != nil {
			return target, fmt.Errorf("enterprise hooks: resolve profile for SID %s: %w", target.sid, err)
		}
		target.home = strings.TrimSpace(home)
	}
	if target.home == "" {
		return target, fmt.Errorf("enterprise hooks: --user, --user-home, or --sid is required")
	}
	if dataDir := strings.TrimSpace(dataDir); dataDir != "" && !filepath.IsAbs(dataDir) {
		return target, fmt.Errorf("enterprise hooks: --data-dir must be absolute")
	}
	return target, nil
}

func enterpriseHookScopedToken(dataDir, connectorName string) (string, error) {
	connectorName = strings.TrimSpace(connectorName)
	if connectorName == "" {
		return "", fmt.Errorf("enterprise hooks: connector is required before minting hook API token")
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return "", fmt.Errorf("enterprise hooks: config data_dir is required before minting hook API token")
	}
	if err := validateEnterpriseHookScopedTokenLocation(dataDir, connectorName); err != nil {
		return "", err
	}
	token, err := connector.EnsureHookAPIToken(dataDir, connectorName)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: ensure scoped hook API token: %w", err)
	}
	if err := alignEnterpriseHookScopedTokenOwner(dataDir, connectorName); err != nil {
		return "", err
	}
	return token, nil
}

func loadEnterpriseHookScopedToken(dataDir, connectorName string) (string, error) {
	connectorName = strings.TrimSpace(connectorName)
	if connectorName == "" {
		return "", fmt.Errorf("enterprise hooks: connector is required before reading hook API token")
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return "", fmt.Errorf("enterprise hooks: config data_dir is required before reading hook API token")
	}
	if err := validateEnterpriseHookScopedTokenLocation(dataDir, connectorName); err != nil {
		return "", err
	}
	token, err := connector.LoadHookAPIToken(dataDir, connectorName)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: read scoped hook API token: %w", err)
	}
	if token == "" {
		return "", fmt.Errorf("enterprise hooks: connector-scoped hook API token is missing for %s", connectorName)
	}
	return token, nil
}

func enterpriseHookScopedOTLPToken(dataDir, connectorName string) (string, error) {
	scope, ok := connector.OTLPPathTokenScopeForConnector(connectorName)
	if !ok {
		return "", nil
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return "", fmt.Errorf("enterprise hooks: config data_dir is required before minting OTLP path token")
	}
	if err := validateEnterpriseOTLPTokenLocation(dataDir, scope); err != nil {
		return "", err
	}
	token, err := connector.EnsureOTLPPathToken(dataDir, scope)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: ensure scoped OTLP path token: %w", err)
	}
	if err := alignEnterpriseOTLPTokenOwner(dataDir, scope); err != nil {
		return "", err
	}
	return token, nil
}

func loadEnterpriseHookScopedOTLPToken(dataDir, connectorName string) (string, error) {
	scope, ok := connector.OTLPPathTokenScopeForConnector(connectorName)
	if !ok {
		return "", nil
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return "", fmt.Errorf("enterprise hooks: config data_dir is required before reading OTLP path token")
	}
	if err := validateEnterpriseOTLPTokenLocation(dataDir, scope); err != nil {
		return "", err
	}
	token, err := connector.LoadOTLPPathToken(dataDir, scope)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: read scoped OTLP path token: %w", err)
	}
	if token == "" {
		return "", fmt.Errorf("enterprise hooks: scoped OTLP path token is missing for %s", connectorName)
	}
	return token, nil
}

func intPtrValue(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
