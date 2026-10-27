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
	"crypto/rand"
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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winsession"
)

// enterpriseHookWatchSessionSettle is the delay between a Windows sign-in
// notification (standalone service host only) and the reconcile it triggers,
// long enough for the new session's user token to become the exact active
// token the guardian impersonates.
var enterpriseHookWatchSessionSettle = 5 * time.Second

// enterpriseHookAccountChangeSettle is the delay between a change of the
// local account database and the reconcile it triggers, so a useradd
// followed by usermod or passwd runs one pass (GAP-2108).
var enterpriseHookAccountChangeSettle = time.Second

// enterpriseHookWatchDebounceMaxWait bounds how long filesystem events can
// postpone the pass they armed. Every event re-armed the debounce with no
// limit, so writes faster than the debounce held the pass back until the
// interval pass, long enough to start an agent without hooks and put the
// file back unseen (GAP-0532). It leaves the pass, its recheck window and
// its repair audit (about 0.9 s on macOS) inside the 3 s repair bound of a
// rewrite burst (r103 GAP-0045, GAP-1825).
var enterpriseHookWatchDebounceMaxWait = 1 * time.Second

// enterpriseHookWatchRecheckWindow is how long a pass armed by a filesystem
// event keeps each protected target under check after it verified. One read
// per pass judged a file that a writer rewrites between its hooks and none
// every 200 ms by whichever phase the read met: the hooks were back at the
// read of most passes, so the first repair came 5-15 s into the burst
// (GAP-1825). Checking for longer than one phase meets the damaged one. The
// windows of a pass's targets run at the same time, after every target was
// checked once, so a pass takes one window longer, not one per target.
var enterpriseHookWatchRecheckWindow = 300 * time.Millisecond

// enterpriseHookRecheckStep is the pause between two checks of a window.
var enterpriseHookRecheckStep = 40 * time.Millisecond

// enterpriseHookReconcileRecheckWindow is the recheck window of the pass
// that runs now: the watch loop sets it for a pass a filesystem event armed.
var enterpriseHookReconcileRecheckWindow time.Duration

// enterpriseHookReconcileRecheckPaths are the paths of the filesystem events
// that armed the pass that runs now; enterpriseHookReconcileRecheckAll is set
// when events were dropped (an overflow) or more paths changed than the watch
// loop keeps. The standalone Unix pass gives the recheck window only to the
// accounts those paths are in: one window per account, run in waves of
// workers, made every pass about 0.3 s longer per wave of four accounts, so a
// change in one home delayed the repair of a home in a later wave
// (GAP-1825 review R4-2).
var (
	enterpriseHookReconcileRecheckPaths []string //nolint:unused // read by the standalone Unix pass (enterprise_hooks_standalone_unix.go)
	enterpriseHookReconcileRecheckAll   bool     //nolint:unused // read by the standalone Unix pass (enterprise_hooks_standalone_unix.go)
)

// enterpriseHookWatchMaxTriggerPaths bounds the paths one pass remembers.
const enterpriseHookWatchMaxTriggerPaths = 64

// enterpriseHookWatchAddTriggerPath adds the cleaned path of an event to the
// pass's trigger paths, once; all is true once more paths changed than the
// bound.
func enterpriseHookWatchAddTriggerPath(paths []string, all bool, name string) ([]string, bool) {
	if all {
		return paths, true
	}
	cleaned := filepath.Clean(name)
	for _, path := range paths {
		if path == cleaned {
			return paths, false
		}
	}
	if len(paths) >= enterpriseHookWatchMaxTriggerPaths {
		return nil, true
	}
	return append(paths, cleaned), false
}

// enterpriseHookWatchRecheckFor is the recheck window of a pass run for reason.
func enterpriseHookWatchRecheckFor(reason string) time.Duration {
	if reason == "fsnotify" {
		return enterpriseHookWatchRecheckWindow
	}
	return 0
}

// recheckEnterpriseHookTargetsOverWindow checks again, round-robin every
// enterpriseHookRecheckStep, the targets of a pass that verified, each until
// window after its first check (checkedAt), and calls failed with the first
// failure of a target, which repairs it; that target is then not checked
// again. All windows of a pass run together (GAP-1825: one window per target
// in turn made each pass 300 ms longer per target and repaired a target late
// in the order seconds later).
func recheckEnterpriseHookTargetsOverWindow(
	ctx context.Context,
	window time.Duration,
	checkedAt []time.Time,
	verify func(int) error,
	failed func(int, error),
) {
	if window <= 0 {
		return
	}
	open := make([]int, 0, len(checkedAt))
	for index := range checkedAt {
		open = append(open, index)
	}
	for len(open) > 0 {
		timer := time.NewTimer(enterpriseHookRecheckStep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		next := open[:0]
		for _, index := range open {
			if !time.Now().Before(checkedAt[index].Add(window)) {
				continue
			}
			if err := verify(index); err != nil {
				failed(index, err)
				continue
			}
			next = append(next, index)
		}
		open = next
	}
}

// enterpriseHookWatchDebounceDelay is the delay to arm the debounce with at
// now for a burst whose first event armed it at first: the debounce, cut to
// what is left of maxWait (never below zero).
func enterpriseHookWatchDebounceDelay(now, first time.Time, debounce, maxWait time.Duration) time.Duration {
	if first.IsZero() || maxWait <= 0 {
		return debounce
	}
	left := maxWait - now.Sub(first)
	if left < 0 {
		left = 0
	}
	if left < debounce {
		return left
	}
	return debounce
}

// enterpriseHookTargetsWaitTimeout is the bounded window the hook-guardian
// will fsnotify-wait for a missing targets.yaml before returning a
// distinguishable error, so the SCM restart cycle picks it back up. Kept
// as a package-level `var` (not a
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
	enterpriseHooksConfigOnlyPersistentPreRun = func(cmd *cobra.Command, _ []string) error {
		return loadGatewayCommandConfigFor(cmd)
	}
	enterpriseHooksPluginRegistryFactory       = newConnectorRegistryWithPlugins
	enterpriseHooksCertifiedRegistryFactory    = newWindowsEnterpriseCertifiedConnectorRegistry
	enterpriseHooksInstallRunE                 = runEnterpriseHooksInstall
	enterpriseHooksUninstallRunE               = runEnterpriseHooksUninstall
	enterpriseHooksReconcileRunE               = runEnterpriseHooksReconcile
	enterpriseHooksWatchRunE                   = runEnterpriseHooksWatch
	enterpriseHooksStatusRunE                  = runEnterpriseHooksStatus
	enterpriseHooksVerifyRunE                  = runEnterpriseHooksVerify
	enterpriseHooksReadinessRunE               = runEnterpriseHooksReadiness
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
	enterpriseHookManifestFileTrustCheck = func(path string) error {
		return managed.ValidateTrustedFilePath(path, "hook guardian manifest")
	}
	enterpriseHooksRemoveManagedPolicy  = enterprisehooks.RemoveManagedPolicy
	enterpriseHookScopedTokenMinter     = enterpriseHookScopedToken
	enterpriseHookScopedOTLPTokenMinter = enterpriseHookScopedOTLPToken
	// The standalone profile's per-user credentials (hook, OTLP) bound to
	// one uid or SID; see connector.UserScopedHookAPIToken.
	enterpriseHookUserTokenMinter = enterpriseHookUserScopedTokens
	enterpriseHookUserTokenLoader = loadEnterpriseHookUserScopedTokens
)

const defaultEnterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
const hookGuardianStateFile = "hook_guardian_state.json"
const hookGuardianAuthorizationFile = managed.HookGuardianAuthorizationFile
const hookGuardianActivationFile = "activation.json"
const hookGuardianAuthorizationDirEnv = managed.HookGuardianAuthorizationDirEnv

const (
	enterpriseHookGuardianStateMaxBytes         int64 = 1 << 20
	enterpriseHookGuardianAuthorizationMaxBytes int64 = 4 << 20
	enterpriseHookGuardianActivationVersion           = 1
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
		err := enterpriseHooksPlatformPreflight()
		if err == nil {
			// Cobra runs only the nearest persistent pre-run hook. Chain the root
			// initializer explicitly so supported hosts retain config, audit, and
			// authorization initialization before any enterprise hook operation.
			err = enterpriseHooksRootPersistentPreRun(cmd, args)
		}
		return enterpriseHooksStatusPreRunJSON(cmd, err)
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
	registry.RegisterBuiltin(connector.NewCursorConnector())
	enterprisehooks.RegisterWindowsStandalonePerUserConnectors(registry)
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

// Setup checks live hook registration before it commits machine readiness.
// Public Verify separately refuses to certify a session-only Hermes home.
var enterpriseHooksReadinessCmd = &cobra.Command{
	Use:    "readiness",
	Short:  "Check live machine hook registration for managed Setup",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return enterpriseHooksReadinessRunE(cmd, args)
	},
}

func init() {
	enterpriseHooksInstallCmd.Flags().StringVar(&enterpriseHookConnector, "connector", "",
		"Hook-native connector to install or repair (codex, claudecode, or cursor on native Windows)")
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
		"Administrator-managed connector to remove (built-in codex, claudecode, or cursor on native Windows)")
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
		"Filesystem-event debounce before reconcile; a burst of events reaches its reconcile within 3s of its first event")
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
	enterpriseHooksReadinessCmd.Flags().StringVar(&enterpriseHookManifest, "manifest", defaultEnterpriseHookManifest,
		"YAML manifest of per-user hook targets")
	enterpriseHooksReadinessCmd.Flags().StringVar(&enterpriseHookAPIAddr, "api-addr", "",
		"Local gateway API host:port used by hook scripts (default: 127.0.0.1:<gateway.api_port>)")
	enterpriseHooksReadinessCmd.Flags().StringVar(&enterpriseHookProxyAddr, "proxy-addr", "",
		"Local guardrail proxy host:port (default: 127.0.0.1:<guardrail.port>)")
	enterpriseHooksReadinessCmd.Flags().BoolVar(&enterpriseHookJSON, "json", false,
		"Emit machine-readable JSON")

	enterpriseHooksCmd.AddCommand(enterpriseHooksInstallCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksUninstallCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksReconcileCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksWatchCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksStatusCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksVerifyCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksReadinessCmd)
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
	if err := enterpriseHookInstallConnectorPublished(cfg, enterpriseHookConnector); err != nil {
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
	// The standalone Unix install resolves the target account in its
	// worker path and derives the target's per-user credentials there.
	token, otlpToken := "", ""
	if !enterpriseHooksStandaloneUnixActive() {
		token, otlpToken, err = enterpriseHookTargetTokens(cfg.DataDir, enterpriseHookConnector, target.sid, true)
		if err != nil {
			return enterpriseHooksInstallError(cmd, err)
		}
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
		// Standalone Amp and OpenCode only; empty on Secure Client. The
		// reconcile verifies with it, so an install without it would be
		// re-rendered on the next pass.
		ForeignHookGuardBinary: standaloneForeignHookGuardBinary(enterpriseHookConnector),
		ManagedHookBinary:      standaloneManagedHookBinary(),
	}
	// A single-target install renders the shared machine policy from the
	// same deployment contract the guardian uses, so the next reconcile does
	// not rewrite the body back.
	machineContract, err := enterpriseHookInstallMachinePolicyContract(enterpriseHookConnector)
	if err != nil {
		return enterpriseHooksInstallError(cmd, err)
	}
	opts.MachinePolicyContractID = machineContract

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	result, err := enterpriseHookInstallTarget(ctx, opts)
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

// enterpriseHookInstallConnectorPublished refuses, on a standalone managed
// deployment, a hook install for a connector the installed config does not
// publish (enterprisepolicy.StandaloneConnectorPublished): its hook would
// get no usable answer from the gateway, so every call of that agent would
// be blocked with a message that does not name the cause (rel-1-0-3
// GAP-0235). Other deployments are unchanged.
func enterpriseHookInstallConnectorPublished(cfg *config.Config, name string) error {
	if cfg == nil || !cfg.StandaloneEnterprise() || strings.TrimSpace(name) == "" {
		return nil
	}
	if enterprisepolicy.StandaloneConnectorPublished(cfg, name) {
		return nil
	}
	published := enterprisepolicy.StandaloneConnectors(cfg)
	list := "none"
	if len(published) > 0 {
		list = strings.Join(published, ", ")
	}
	return fmt.Errorf("enterprise hooks install: connector %q is not enabled by this computer's DefenseClaw configuration "+
		"(enabled: %s), so its hooks would block every call; add it under guardrail.connectors in the "+
		"administrator config and run ensure, which installs its hooks for every enrolled account",
		config.NormalizeConnectorName(name), list)
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
	User      string `json:"user,omitempty"`
	UserHome  string `json:"user_home,omitempty"`
	SID       string `json:"sid,omitempty"`
	Connector string `json:"connector"`
	OK        bool   `json:"ok"`
	// Pending is valid only for an administrator-authored deferred manifest
	// row whose exact WTSActive token is currently unavailable.
	Pending bool                           `json:"pending,omitempty"`
	Error   string                         `json:"error,omitempty"`
	Result  *enterprisehooks.InstallResult `json:"result,omitempty"`
	// UID and HomeInode identify a standalone Unix target so the gateway
	// can authorize a hook caller by kernel-verified uid, including
	// directory users a cgo-free build cannot name-resolve. Other
	// deployments never set them, so their records are unchanged.
	UID       int    `json:"uid,omitempty"`
	HomeInode uint64 `json:"home_inode,omitempty"`
	// RevokeProtection marks a target whose prior protected row must not be
	// carried forward: a failed standalone Unix target whose account
	// identity changed (its name now maps to another uid, or its old uid
	// now belongs to another account), and a Windows Secure Client target a
	// non-purge uninstall retired, which is pending now. It is never
	// serialized.
	RevokeProtection bool `json:"-"`
}

type enterpriseHookReconcileRun struct {
	Manifest       string
	ManifestSHA256 string
	// Targets are the targets of the manifest the run reconciled (standalone
	// Unix only): under manifest enrollment they, not the eligible-accounts
	// record, say who is enrolled (GAP-0761).
	Targets             []enterprisehooks.ManifestTarget
	Rows                []enterpriseHookReconcileRow
	Failures            int
	Pending             int
	Repairs             int `json:"-"`
	StateErr            error
	WatchDirs           []string
	WatchExclusiveFiles []string // DC-only writers: react to any event
	WatchSharedFiles    []string // agent + DC writers: react only to Create/Remove/Rename
}

var (
	enterpriseHookReconcileVerifier         = enterpriseHookGuardianVerify
	enterpriseHookReconcileInstaller        = enterprisehooks.Install
	enterpriseHookReconcileSessionAvailable = enterpriseHookTargetSessionAvailable
	// enterpriseHookReconcileTargetRelease names the other DefenseClaw
	// release whose hook-contract lock a target still carries. Tests
	// replace it.
	enterpriseHookReconcileTargetRelease = enterprisehooks.WindowsProtectedTargetFromOtherRelease
	// enterpriseHookReconcileTargetFailModeChange returns the hook fail mode
	// a target's lock records and the one the config asks for. Tests
	// replace it.
	enterpriseHookReconcileTargetFailModeChange = enterprisehooks.WindowsProtectedTargetHookFailModeChange
	// enterpriseHookReconcileClosingLogon proves a logon the guardian can
	// close a target's hook fail mode under while its account has no active
	// session (enterprisehooks.WindowsTargetLogonAnyWithS4U), without acting
	// as the account; ErrEnrolledUserSignedOut when Windows gives none.
	// Tests replace it.
	enterpriseHookReconcileClosingLogon = enterpriseHookTargetClosingLogon
	// enterpriseHookReconcileSecureClient reports a Secure Client guardian.
	// Tests replace it.
	enterpriseHookReconcileSecureClient = enterprisehooks.WindowsSecureClientProfileProcess
	// enterpriseHookSessionCheckNotLocalSystem reports a session check
	// refused because this process is not LocalSystem. Tests replace it.
	enterpriseHookSessionCheckNotLocalSystem = enterprisehooks.IsWindowsEnterpriseNotLocalSystem
	// The reconcile's deferred-session check and machine-enrollment steps.
	// Tests replace them.
	enterpriseHookReconcileDeferredSessionAvailable = enterpriseHookDeferredTargetSessionAvailable
	enterpriseHookReconcileStageDeferredPolicies    = stageEnterpriseHookDeferredManagedPolicies
	enterpriseHookReconcileSyncEnrollments          = syncEnterpriseHookManagedEnrollments
)

// enterpriseHookAwaitingSignInPrefix starts the guardian error of a target
// an earlier DefenseClaw release protected that fails this release's
// verification while its account is signed out (GAP-0644). An upgrade
// renders new hooks that only the account's own Windows session installs,
// and Windows 11 signs in one account at a time, so such a target waits for
// that account's next sign-in, when the guardian repairs it. Status, verify
// and Setup report it as pending until then, not as protected; the
// protected records keep it as an unrepaired row (its last protected row
// stays authorized for that repair). The error goes on to say the session
// is unavailable, as every signed-out repair error does.
const enterpriseHookAwaitingSignInPrefix = "enterprise hooks: protected target waits for its account's next sign-in"

// errEnterpriseHookAwaitingSignIn marks the reconcile error of such a
// target, so the reconcile counts exactly the rows it left waiting.
var errEnterpriseHookAwaitingSignIn = errors.New(enterpriseHookAwaitingSignInPrefix)

// The causes of a sign-in wait start the error after the prefix, so status
// and verify say why the target waits (enterpriseHookAwaitingSignInCause):
// another release protected it (GAP-0644), or a hook fail mode change left
// its hooks failing closed or open until the guardian renders the new mode
// (GAP-0585).
const (
	enterpriseHookAwaitingSignInFailClosed = "its hooks fail closed"
	enterpriseHookAwaitingSignInFailOpen   = "its hooks keep hook fail mode open"
	// A signed-out account's Hermes home is unobservable (GAP-1433).
	enterpriseHookAwaitingSignInHermesHome = "its Hermes home cannot be read while the account is signed out"
)

// enterpriseHookAwaitingSignInCause words, for status and verify, why a
// guardian row that waits for its account's next sign-in (its error) is not
// in its configured state yet.
func enterpriseHookAwaitingSignInCause(guardianErr string) string {
	cause := strings.TrimPrefix(strings.TrimSpace(guardianErr), enterpriseHookAwaitingSignInPrefix+": ")
	switch {
	case strings.HasPrefix(cause, enterpriseHookAwaitingSignInFailClosed):
		return "its hooks still fail closed, and the guardian renders hook fail mode open in the account's own " +
			"Windows session at its next sign-in"
	case strings.HasPrefix(cause, enterpriseHookAwaitingSignInHermesHome):
		return "Hermes NOT COVERED: the account is signed out, so its registry hive and the HERMES_HOME it selects " +
			"cannot be read; its installed hook is unchanged, and the guardian verifies it again at the account's next sign-in"
	case strings.HasPrefix(cause, enterpriseHookAwaitingSignInFailOpen):
		return "Windows gave no S4U logon to close its hooks while the account is signed out, so they keep hook " +
			"fail mode open, allowing calls during a gateway outage, until the guardian closes them at the " +
			"account's next sign-in"
	default:
		return "an earlier DefenseClaw release protected it, and the guardian installs this release's hooks only " +
			"in the account's own Windows session, at its next sign-in; it is not protected until then"
	}
}

// errEnterpriseHookProtectionRetired marks a Secure Client deferred target a
// committed non-purge uninstall retired: its protected records survived in
// the retained StateRoot, but its machine enrollment and runtime selector
// are gone, so it holds nothing protected and is pending like an account
// DefenseClaw never protected.
var errEnterpriseHookProtectionRetired = errors.New("enterprise hooks: protected target was retired by an uninstall")

// enterpriseHookReconcileRecheck is a target of the in-process reconcile
// that verified and is checked again over the pass's recheck window.
type enterpriseHookReconcileRecheck struct {
	row    int
	target enterprisehooks.ManifestTarget
	opts   enterprisehooks.InstallOptions
}

// enterpriseHookVerifyOrRepairTarget keeps repair classification adjacent to
// the operation that proves it. A target is repaired only when it was already
// protected, verification failed, its authenticated session was available
// (for a change that closes the hook fail mode, a disconnected session or an
// S4U logon also serves), and the subsequent install completed successfully.
func enterpriseHookVerifyOrRepairTarget(
	ctx context.Context,
	target enterprisehooks.ManifestTarget,
	opts enterprisehooks.InstallOptions,
	previouslyProtected bool,
) (enterprisehooks.InstallResult, bool, error) {
	if !previouslyProtected {
		result, err := enterpriseHookReconcileInstaller(ctx, opts)
		return result, false, err
	}
	result, verifyErr := enterpriseHookReconcileVerifier(ctx, opts)
	if verifyErr == nil {
		return enterpriseHookRetryNativeOTLPTakeBack(ctx, target, opts, result), false, nil
	}
	return enterpriseHookRepairAfterVerifyFailure(ctx, target, opts, verifyErr)
}

// enterpriseHookRepairAfterVerifyFailure repairs a previously protected
// target whose verification failed with verifyErr, under the session rules
// of enterpriseHookVerifyOrRepairTarget.
func enterpriseHookRepairAfterVerifyFailure(
	ctx context.Context,
	target enterprisehooks.ManifestTarget,
	opts enterprisehooks.InstallOptions,
	verifyErr error,
) (enterprisehooks.InstallResult, bool, error) {
	available, err := enterpriseHookReconcileSessionAvailable(target)
	if err != nil {
		return enterprisehooks.InstallResult{}, false, err
	}
	if !available {
		// Only a deferred target whose lock another release wrote, or one a
		// hook fail mode change alone made fail, waits for the sign-in (a
		// change to closed is rendered now when Windows gives a logon for
		// it). One this release protected that no longer verifies
		// was changed while its account was signed out, and stays a failure,
		// unless on Secure Client a committed non-purge uninstall retired it:
		// a reinstall over the retained StateRoot then found every
		// signed-out account's target drifted and failed with 1603. With no
		// runtime selected for it (the pending proof), it holds nothing
		// protected and is pending until the account signs in, its hooks
		// failing closed as a pending target's do.
		if target.IsDeferred() {
			// A signed-out account's Hermes home is unobservable, not
			// changed: Windows has not loaded the registry hive that holds
			// its HERMES_HOME. One account signing out never fails the host;
			// the target waits for that account's sign-in (GAP-1433).
			if !enterpriseHookReconcileSecureClient() &&
				strings.EqualFold(strings.TrimSpace(target.Connector), "hermes") &&
				errors.Is(verifyErr, hermespath.ErrAccountSignedOut) {
				return enterprisehooks.InstallResult{}, false, fmt.Errorf(
					"%w: %s, so Hermes is NOT COVERED for it until the guardian verifies it at its next sign-in; "+
						"its exact active Windows session is unavailable (verification: %v)",
					errEnterpriseHookAwaitingSignIn, enterpriseHookAwaitingSignInHermesHome, verifyErr,
				)
			}
			if written, other, releaseErr := enterpriseHookReconcileTargetRelease(opts); releaseErr == nil && other {
				return enterprisehooks.InstallResult{}, false, fmt.Errorf(
					"%w: DefenseClaw %s protected it, and this release's hooks install only in the account's own "+
						"Windows session; its exact active Windows session is unavailable, so the guardian repairs "+
						"it at the account's next sign-in (verification: %v)",
					errEnterpriseHookAwaitingSignIn, written, verifyErr,
				)
			}
			if enterpriseHookReconcileSecureClient() {
				if available, pendingErr := enterpriseHookReconcileDeferredSessionAvailable(target); pendingErr == nil && !available {
					return enterprisehooks.InstallResult{}, false, fmt.Errorf(
						"%w (verification: %v): %w",
						errEnterpriseHookProtectionRetired, verifyErr,
						&enterprisehooks.WindowsTargetSessionUnavailableError{SID: strings.TrimSpace(target.SID)},
					)
				}
			}
			if locked, wanted, modeErr := enterpriseHookReconcileTargetFailModeChange(opts); modeErr == nil &&
				locked != "" && locked != wanted {
				if result, repaired, handled, err := enterpriseHookFailModeChangeWithoutSession(
					ctx, target, opts, locked, wanted, verifyErr,
				); handled {
					return result, repaired, err
				}
			}
		}
		return enterprisehooks.InstallResult{}, false, fmt.Errorf(
			"enterprise hooks: protected target requires repair but its exact active Windows session is unavailable (verification: %v)",
			verifyErr,
		)
	}
	result, err := enterpriseHookReconcileInstaller(ctx, opts)
	return result, err == nil, err
}

// enterpriseHookFailModeChangeWithoutSession handles a deferred target an
// administrator's hook fail mode change (from locked to wanted) made fail
// verification while its account has no active session (rel-1-0-4
// GAP-0585). A Setup that failed it rolled the whole host back to the old
// mode. A change to open waits for the account's next sign-in while the
// fail mode is the only drift: its hooks fail closed until then. A change
// to closed is rendered now, under the account's disconnected session or an
// S4U logon; only when Windows gives neither, and the fail mode is the only
// drift, does it wait for the sign-in, the change committed for everyone
// else. Any other drift is not handled here and stays a failure.
func enterpriseHookFailModeChangeWithoutSession(
	ctx context.Context,
	target enterprisehooks.ManifestTarget,
	opts enterprisehooks.InstallOptions,
	locked, wanted string,
	verifyErr error,
) (result enterprisehooks.InstallResult, repaired, handled bool, err error) {
	var signedOut error
	if wanted == "closed" {
		signedOut = enterpriseHookReconcileClosingLogon(target)
		if signedOut == nil {
			closing := opts
			closing.WindowsTargetLogon = enterprisehooks.WindowsTargetLogonAnyWithS4U
			result, err = enterpriseHookReconcileInstaller(ctx, closing)
			return result, err == nil, true, err
		}
		if !errors.Is(signedOut, enterprisehooks.ErrEnrolledUserSignedOut) {
			return enterprisehooks.InstallResult{}, false, true, signedOut
		}
	}
	rendered := opts
	rendered.HookFailMode = locked
	if _, renderedErr := enterpriseHookReconcileVerifier(ctx, rendered); renderedErr != nil {
		return enterprisehooks.InstallResult{}, false, false, nil
	}
	if wanted == "closed" {
		return enterprisehooks.InstallResult{}, false, true, fmt.Errorf(
			"%w: %s until the account's next sign-in, when the guardian closes them; %v (verification: %v)",
			errEnterpriseHookAwaitingSignIn, enterpriseHookAwaitingSignInFailOpen, signedOut, verifyErr,
		)
	}
	return enterprisehooks.InstallResult{}, false, true, fmt.Errorf(
		"%w: %s, and hook fail mode open installs only in the account's own Windows session; its exact active "+
			"Windows session is unavailable, so the guardian repairs it at the account's next sign-in (verification: %v)",
		errEnterpriseHookAwaitingSignIn, enterpriseHookAwaitingSignInFailClosed, verifyErr,
	)
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
		label := enterpriseHookReconcileRowLabel(row)
		if row.OK {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s reconciled%s\n", Style("✓", "fg=green", "bold"), label, enterpriseHookAgentVersionNote(row))
		} else if row.Pending {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s pending an exact active Windows session\n", Style("•", "fg=yellow", "bold"), label)
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

// enterpriseHookAgentVersionNote names an untested newer agent version on a
// reconcile or verify line.
func enterpriseHookAgentVersionNote(row enterpriseHookReconcileRow) string {
	if row.Result == nil || row.Result.AgentVersionStatus == "" {
		return ""
	}
	return fmt.Sprintf(" (%s %s)", row.Result.AgentVersionStatus, strings.TrimSpace(row.Result.AgentVersion))
}

type enterpriseHookStatusReport struct {
	Enabled                       bool                                 `json:"enabled"`
	OK                            bool                                 `json:"ok"`
	StateFile                     string                               `json:"state_file"`
	AuthorizationFile             string                               `json:"authorization_file"`
	State                         *enterpriseHookGuardianState         `json:"state,omitempty"`
	Authorization                 *enterpriseHookGuardianAuthorization `json:"authorization,omitempty"`
	Activation                    *enterpriseHookGuardianActivation    `json:"activation,omitempty"`
	Verification                  []enterpriseHookReconcileRow         `json:"verification,omitempty"`
	ClaudeEffectivePolicyVerified bool                                 `json:"claude_effective_policy_verified"`
	// Enrollment lists, per enrolled account, each connector and its state
	// in the last guardian reconcile.
	Enrollment []enterpriseHookEnrollment `json:"enrollment,omitempty"`
	Errors     []string                   `json:"errors,omitempty"`
	// Warnings name rows that do not fail the host: those of a deleted
	// account and those waiting for their account's next sign-in
	// (enterpriseHookExcusedFailures).
	Warnings []string `json:"warnings,omitempty"`
	// RemovedAccountFailures and AwaitingSignInFailures count those rows, so
	// the Windows lifecycle's manifest adoption accepts exactly them, as
	// verify does.
	RemovedAccountFailures int `json:"removed_account_failures,omitempty"`
	AwaitingSignInFailures int `json:"awaiting_sign_in_failures,omitempty"`
}

// enterpriseHookEnrollment is one account's connectors in the last
// guardian reconcile.
type enterpriseHookEnrollment struct {
	User       string                          `json:"user,omitempty"`
	UserHome   string                          `json:"user_home,omitempty"`
	SID        string                          `json:"sid,omitempty"`
	UID        int                             `json:"uid,omitempty"`
	Connectors []enterpriseHookEnrollmentState `json:"connectors"`
	// AccountDeleted marks an account whose home no longer exists: it was
	// deleted, and its rows last until the hook enumerator's next pass
	// (GAP-1867).
	AccountDeleted bool `json:"account_deleted,omitempty"`
}

// enterpriseHookEnrollmentState is one connector's state for an account:
// "enrolled", "pending" (waiting for the user's session) or "failed".
type enterpriseHookEnrollmentState struct {
	Connector string `json:"connector"`
	State     string `json:"state"`
}

// enterpriseHookEnrollmentFromRows groups reconcile rows by account, in
// account then connector order.
func enterpriseHookEnrollmentFromRows(rows []enterpriseHookReconcileRow) []enterpriseHookEnrollment {
	byAccount := map[string]*enterpriseHookEnrollment{}
	var keys []string
	for _, row := range rows {
		key := strings.TrimSpace(row.SID)
		if key == "" {
			key = strings.TrimSpace(row.User)
		}
		if key == "" {
			key = strings.TrimSpace(row.UserHome)
		}
		entry, seen := byAccount[key]
		if !seen {
			entry = &enterpriseHookEnrollment{User: row.User, UserHome: row.UserHome, SID: row.SID, UID: row.UID}
			byAccount[key] = entry
			keys = append(keys, key)
		}
		state := "failed"
		switch {
		case row.OK:
			state = "enrolled"
		case row.Pending, enterpriseHookAwaitingSignInError(row):
			state = "pending"
		}
		entry.Connectors = append(entry.Connectors, enterpriseHookEnrollmentState{
			Connector: strings.TrimSpace(row.Connector), State: state,
		})
	}
	sort.Strings(keys)
	out := make([]enterpriseHookEnrollment, 0, len(keys))
	for _, key := range keys {
		entry := byAccount[key]
		sort.SliceStable(entry.Connectors, func(i, j int) bool {
			return entry.Connectors[i].Connector < entry.Connectors[j].Connector
		})
		out = append(out, *entry)
	}
	return out
}

// markEnterpriseHookDeletedAccounts sets AccountDeleted on each account whose
// home is gone and that has no connector the last reconcile verified there.
// Status listed such an account with its agents pending for the minutes
// until the enumerator dropped it, as if it would still enroll.
func markEnterpriseHookDeletedAccounts(enrollment []enterpriseHookEnrollment) {
	for i := range enrollment {
		home := strings.TrimSpace(enrollment[i].UserHome)
		if home == "" || slices.ContainsFunc(enrollment[i].Connectors, func(state enterpriseHookEnrollmentState) bool {
			return state.State == "enrolled"
		}) {
			continue
		}
		if _, err := os.Lstat(home); errors.Is(err, os.ErrNotExist) {
			enrollment[i].AccountDeleted = true
		}
	}
}

// printEnterpriseHookEnrollment renders the per-account enrollment list.
func printEnterpriseHookEnrollment(w io.Writer, enrollment []enterpriseHookEnrollment, updatedAt string) {
	if len(enrollment) == 0 {
		return
	}
	heading := "Enrollment"
	if strings.TrimSpace(updatedAt) != "" {
		heading += " (last guardian reconcile " + strings.TrimSpace(updatedAt) + ")"
	}
	fmt.Fprintf(w, "  %s:\n", heading)
	for _, account := range enrollment {
		label := strings.TrimSpace(account.User)
		var detail []string
		if home := strings.TrimSpace(account.UserHome); home != "" && home != label {
			if label == "" {
				label = home
			} else {
				detail = append(detail, home)
			}
		}
		if sid := strings.TrimSpace(account.SID); sid != "" {
			if label == "" {
				label = sid
			} else {
				detail = append(detail, sid)
			}
		}
		if account.UID > 0 {
			detail = append(detail, fmt.Sprintf("uid %d", account.UID))
		}
		if len(detail) > 0 {
			label += " (" + strings.Join(detail, ", ") + ")"
		}
		connectors := make([]string, 0, len(account.Connectors))
		for _, connector := range account.Connectors {
			if account.AccountDeleted {
				connectors = append(connectors, connector.Connector)
				continue
			}
			connectors = append(connectors, connector.Connector+" "+connector.State)
		}
		if account.AccountDeleted {
			fmt.Fprintf(w, "    %s: account deleted, home removed (%s dropped at the hook enumerator's next pass)\n", label, strings.Join(connectors, ", "))
			continue
		}
		fmt.Fprintf(w, "    %s: %s\n", label, strings.Join(connectors, ", "))
	}
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
	manifestSHA256 := ""
	if err := enterpriseHookManifestFileTrustCheck(enterpriseHookManifest); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("hook guardian manifest trust check failed: %v", err))
	} else {
		_, digest, err := enterprisehooks.LoadManifestWithSHA256(enterpriseHookManifest)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			manifestSHA256 = digest
		}
	}

	records := loadEnterpriseHookGuardianRecords(cfg.DataDir)
	state, stateExists, stateErr := records.State, records.StateExists, records.StateErr
	excusedFailures := 0
	if stateErr != nil {
		report.Errors = append(report.Errors, stateErr.Error())
	} else if !stateExists {
		report.Errors = append(report.Errors, "hook guardian has not completed a reconcile")
	} else {
		report.State = &state
		report.RemovedAccountFailures, report.AwaitingSignInFailures = enterpriseHookExcusedFailures(state)
		excusedFailures = report.RemovedAccountFailures + report.AwaitingSignInFailures
		for _, row := range state.Results {
			if row.OK || row.Pending {
				continue
			}
			issue := enterpriseHookGuardianFailureIssue(row)
			switch {
			case excusedFailures == 0:
				report.Errors = append(report.Errors, issue)
			case enterpriseHookAwaitingSignInRow(row):
				report.Warnings = append(report.Warnings, issue)
			default:
				report.Warnings = append(report.Warnings, issue+enterpriseHookRemovedAccountNote)
			}
		}
		report.Enrollment = enterpriseHookEnrollmentFromRows(state.Results)
		markEnterpriseHookDeletedAccounts(report.Enrollment)
	}
	authorization, authorizationExists, authorizationErr := records.Authorization, records.AuthorizationExists, records.AuthorizationErr
	if authorizationErr != nil {
		report.Errors = append(report.Errors, authorizationErr.Error())
	} else if !authorizationExists {
		report.Errors = append(report.Errors, "protected hook guardian authorization is missing")
	} else {
		report.Authorization = &authorization
	}
	activation, activationExists, activationErr := records.Activation, records.ActivationExists, records.ActivationErr
	if activationErr != nil {
		report.Errors = append(report.Errors, activationErr.Error())
	} else if !activationExists {
		report.Errors = append(report.Errors, "protected hook guardian activation is missing")
	} else {
		report.Activation = &activation
	}
	if stateExists && authorizationExists && activationExists &&
		stateErr == nil && authorizationErr == nil && activationErr == nil {
		expectedManifestSHA256 := manifestSHA256
		if manifestSHA256 != "" && activation.ManifestSHA256 != manifestSHA256 && enterpriseHookManifestCatchUpAllowed() {
			expectedManifestSHA256 = ""
			message, waiting := enterpriseHookManifestActivationIssue(enterpriseHookManifest, manifestSHA256, activation, time.Now())
			if waiting {
				report.Warnings = append(report.Warnings, message)
			} else {
				report.Errors = append(report.Errors, message)
			}
		}
		report.Errors = append(report.Errors, compareEnterpriseHookGuardianRecordsExcusing(
			state,
			authorization,
			activation,
			enterpriseHookManifest,
			expectedManifestSHA256,
			excusedFailures,
		)...)
		// The Guardian is the trusted live verifier on native Windows: it runs
		// as LocalSystem, reconciles every enabled target, and publishes this
		// bounded result together with an independently protected authorization
		// record. Reopening target-owned files here would perform the same checks
		// under the status caller's token, which is not necessarily authorized to
		// read those protected files. Treat only the fresh, matching pair above as
		// the status verification result; the explicit `verify` command remains
		// the caller-token, point-in-time diagnostic path.
		report.Verification = append([]enterpriseHookReconcileRow(nil), state.Results...)
		report.ClaudeEffectivePolicyVerified =
			enterpriseHooksClaudeEffectivePolicyVerified(state.Results)
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
		fmt.Fprintf(cmd.OutOrStdout(), "  %s enterprise hook guardian healthy (%d verified, %d pending, %d total)\n",
			Style("✓", "fg=green", "bold"), state.SuccessCount, state.PendingCount+report.AwaitingSignInFailures, state.TargetCount)
		for _, warning := range report.Warnings {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s\n", Style("•", "fg=yellow", "bold"), warning)
		}
		printEnterpriseHookEnrollment(cmd.OutOrStdout(), report.Enrollment, state.UpdatedAt)
		return nil
	}
	for _, issue := range report.Errors {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s %s\n", Style("✗", "fg=red", "bold"), issue)
	}
	if report.State != nil {
		printEnterpriseHookEnrollment(cmd.OutOrStdout(), report.Enrollment, report.State.UpdatedAt)
	}
	return fmt.Errorf("enterprise hooks status unhealthy")
}

// enterpriseHooksStatusPreRunJSON answers `enterprise hooks status --json`
// run by hand that failed before the status ran (on a managed Windows
// computer an elevated prompt has no per-user config) with its report:
// ok=false and the reason in errors[], with no "Error:" line, instead of an
// empty stdout (GAP-2456). The managed services and the lifecycle run it
// under the deployment-mode pin and keep their output.
func enterpriseHooksStatusPreRunJSON(cmd *cobra.Command, err error) error {
	if err == nil || cmd != enterpriseHooksStatusCmd || !enterpriseHookJSON ||
		managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return err
	}
	_ = json.NewEncoder(cmd.OutOrStdout()).Encode(enterpriseHookStatusReport{Errors: []string{err.Error()}})
	cmd.SilenceErrors = true
	return err
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

// enterpriseHookManifestCatchUpWindow is how long standalone status waits,
// after the enumerator republishes targets.yaml, for the guardian to
// activate it. The guardian reconciles a changed manifest within seconds and
// runs at least once a minute.
const enterpriseHookManifestCatchUpWindow = 2 * time.Minute

// enterpriseHookManifestActivationIssue words, for standalone status, a
// guardian activation of other targets.yaml bytes than the installed ones.
// A targets.yaml the enumerator changed less than
// enterpriseHookManifestCatchUpWindow ago is the guardian catching up
// (waiting): until it activates the new file the gateway keeps enforcing
// the targets it last activated. The change can predate that activation's
// stamp: the guardian reads targets.yaml when a reconcile starts and stamps
// the activation when it ends.
func enterpriseHookManifestActivationIssue(
	manifestPath, manifestSHA256 string,
	activation enterpriseHookGuardianActivation,
	now time.Time,
) (message string, waiting bool) {
	activatedAt, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(activation.UpdatedAt))
	if info, statErr := os.Stat(manifestPath); statErr == nil {
		changedAt := info.ModTime().UTC()
		if age := now.Sub(changedAt); age >= 0 && age < enterpriseHookManifestCatchUpWindow {
			return fmt.Sprintf("the hook enumerator updated targets.yaml %s ago and the hook guardian has not activated it yet; "+
				"it does within about a minute, and until then enforces the targets it last activated", age.Round(time.Second)), true
		}
		if parseErr == nil && changedAt.After(activatedAt) {
			return fmt.Sprintf("the hook guardian has not activated the targets.yaml the enumerator published at %s "+
				"(its last activation was at %s); check that the hook guardian service is running and read its log",
				changedAt.Format(time.RFC3339), activatedAt.UTC().Format(time.RFC3339)), false
		}
	}
	return fmt.Sprintf("the hook guardian last activated other targets.yaml bytes than the installed file "+
		"(activated %.12s, installed %.12s); check that the hook guardian service is running and read its log",
		activation.ManifestSHA256, manifestSHA256), false
}

// enterpriseHookExcusedFailures counts the failed rows of the last reconcile
// that do not fail the host: those of an account confirmed removed by the
// platform (enterpriseHookRemovedAccountRow), which the enumerator
// eventually drops, and those waiting for their signed-out account's next
// sign-in (enterpriseHookAwaitingSignInRow). Both counts are 0 unless every
// failed row is one of them; status and verify then report them as
// warnings instead of failing the whole host.
func enterpriseHookExcusedFailures(state enterpriseHookGuardianState) (removed, awaiting int) {
	for _, row := range state.Results {
		if row.OK || row.Pending {
			continue
		}
		switch {
		case enterpriseHookRemovedAccountRow(row):
			removed++
		case enterpriseHookAwaitingSignInRow(row):
			awaiting++
		default:
			return 0, 0
		}
	}
	if removed+awaiting != state.FailureCount {
		return 0, 0
	}
	return removed, awaiting
}

// enterpriseHookAwaitingSignInRow reports, on a standalone or Secure Client
// deployment, a guardian row that waits for its signed-out account's next
// sign-in (enterpriseHookAwaitingSignInPrefix). It is not protected until
// the guardian repairs it then.
func enterpriseHookAwaitingSignInRow(row enterpriseHookReconcileRow) bool {
	return cfg != nil && (cfg.StandaloneEnterprise() || cfg.SecureClientIntegration()) &&
		enterpriseHookAwaitingSignInError(row)
}

// enterpriseHookAwaitingSignInError is enterpriseHookAwaitingSignInRow for
// readers of the Windows guardian's own records, which load no config; only
// that guardian writes the error.
func enterpriseHookAwaitingSignInError(row enterpriseHookReconcileRow) bool {
	return !row.OK && !row.Pending &&
		strings.HasPrefix(strings.TrimSpace(row.Error), enterpriseHookAwaitingSignInPrefix)
}

func enterpriseHookGuardianFailureIssues(state enterpriseHookGuardianState) []string {
	issues := make([]string, 0, state.FailureCount)
	for _, row := range state.Results {
		if row.OK || row.Pending {
			continue
		}
		issues = append(issues, enterpriseHookGuardianFailureIssue(row))
	}
	return issues
}

// enterpriseHookGuardianFailureIssue words one failed row of the last
// reconcile for status.
func enterpriseHookGuardianFailureIssue(row enterpriseHookReconcileRow) string {
	account := enterpriseHookSignedOutAccount(row)
	if enterpriseHookAwaitingSignInRow(row) {
		if account == "" {
			account = enterpriseHookTargetIssueLabel(row)
		}
		return fmt.Sprintf("%s for %s is pending until that account signs in: %s",
			strings.TrimSpace(row.Connector), account, enterpriseHookAwaitingSignInCause(row.Error))
	}
	if account != "" {
		// The same next step the refused repair gives: nothing an
		// administrator runs helps until the account signs in.
		return fmt.Sprintf(
			"the guardian cannot repair %s for %s while that account is signed out: have the account sign in, "+
				"or remove it with its profile, then run repair again. The guardian repairs DefenseClaw hooks "+
				"only in the account's own Windows session",
			strings.TrimSpace(row.Connector), account)
	}
	detail := strings.TrimSpace(row.Error)
	if detail == "" {
		detail = "no target error was recorded"
	}
	return fmt.Sprintf("last guardian reconcile failed for %s: %s", enterpriseHookTargetIssueLabel(row), detail)
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
	if state.Version != 1 ||
		state.TargetCount < 0 || state.SuccessCount < 0 || state.FailureCount < 0 || state.PendingCount < 0 ||
		state.SuccessCount+state.FailureCount+state.PendingCount != state.TargetCount || len(state.Results) != state.TargetCount {
		return enterpriseHookGuardianState{}, true, fmt.Errorf("hook guardian state %s has invalid schema or target counts", path)
	}
	observedPending := 0
	for _, row := range state.Results {
		if row.Pending {
			observedPending++
		}
		if row.Pending && (row.OK || row.Result != nil || strings.TrimSpace(row.Error) != "") {
			return enterpriseHookGuardianState{}, true, fmt.Errorf("hook guardian state %s has a noncanonical pending target", path)
		}
	}
	if observedPending != state.PendingCount {
		return enterpriseHookGuardianState{}, true, fmt.Errorf("hook guardian state %s has inconsistent pending rows", path)
	}
	return state, true, nil
}

func compareEnterpriseHookGuardianRecords(
	state enterpriseHookGuardianState,
	authorization enterpriseHookGuardianAuthorization,
	activation enterpriseHookGuardianActivation,
	expectedManifest,
	expectedManifestSHA256 string,
) []string {
	return compareEnterpriseHookGuardianRecordsExcusing(
		state, authorization, activation, expectedManifest, expectedManifestSHA256, 0,
	)
}

// enterpriseHookGuardianRecordComplete reports whether a guardian record
// accounts for every target. Its only failures may be the excused ones
// (enterpriseHookExcusedFailures); the guardian never writes a record
// with failures OK.
func enterpriseHookGuardianRecordComplete(ok bool, successes, failures, pending, total, excused int) bool {
	if excused > 0 {
		return failures == excused && successes+pending+failures == total
	}
	return ok && failures == 0 && successes+pending == total
}

// enterpriseHookPartialGuardianRecord reports a protected guardian record
// pair of a pass in which some targets failed but every target has exactly
// one disposition. Only the hidden registration readiness accepts such a
// pass: it proves each other target, while the failed ones stay failures
// and readiness stays not ok. Public verify keeps requiring a complete pass.
func enterpriseHookPartialGuardianRecord(
	authorization enterpriseHookGuardianAuthorization,
	activation enterpriseHookGuardianActivation,
) bool {
	return !authorization.OK && !activation.OK && authorization.FailureCount > 0 &&
		authorization.SuccessCount+authorization.PendingCount+authorization.FailureCount == authorization.TargetCount &&
		activation.SuccessCount+activation.PendingCount+activation.FailureCount == activation.TargetCount
}

// enterpriseHookPartialRegistrationProof is run with each currently failed
// row excused from the protected disposition comparison: the protected
// records carry forward a failed target's prior row, which proves nothing
// about current readiness. The run itself is unchanged.
func enterpriseHookPartialRegistrationProof(run enterpriseHookVerifyRun) enterpriseHookVerifyRun {
	proof := run
	proof.Excused = append([]enterpriseHookReconcileRow(nil), run.Excused...)
	for _, row := range run.Rows {
		if !row.OK && !row.Pending && !enterpriseHookVerifyRowExcused(run, row) {
			proof.Excused = append(proof.Excused, row)
		}
	}
	return proof
}

// compareEnterpriseHookGuardianRecordsExcusing is
// compareEnterpriseHookGuardianRecords that accepts exactly excused failed
// rows (enterpriseHookExcusedFailures) in all three records.
func compareEnterpriseHookGuardianRecordsExcusing(
	state enterpriseHookGuardianState,
	authorization enterpriseHookGuardianAuthorization,
	activation enterpriseHookGuardianActivation,
	expectedManifest,
	expectedManifestSHA256 string,
	excused int,
) []string {
	var issues []string
	now := time.Now()
	if err := managed.ValidateHookGuardianFreshness(state.UpdatedAt, now); err != nil {
		issues = append(issues, fmt.Sprintf("hook guardian state is not fresh: %v", err))
	}
	if err := managed.ValidateHookGuardianFreshness(authorization.UpdatedAt, now); err != nil {
		issues = append(issues, fmt.Sprintf("protected guardian authorization is not fresh: %v", err))
	}
	if err := managed.ValidateHookGuardianFreshness(activation.UpdatedAt, now); err != nil {
		issues = append(issues, fmt.Sprintf("protected guardian activation is not fresh: %v", err))
	}
	if !enterpriseHookGuardianRecordComplete(state.OK, state.SuccessCount, state.FailureCount, state.PendingCount, state.TargetCount, excused) {
		issues = append(issues, fmt.Sprintf("last guardian reconcile is incomplete (%d succeeded, %d pending, %d total)", state.SuccessCount, state.PendingCount, state.TargetCount))
	}
	if !enterpriseHookGuardianRecordComplete(authorization.OK, authorization.SuccessCount, authorization.FailureCount, authorization.PendingCount, authorization.TargetCount, excused) {
		issues = append(issues, fmt.Sprintf("protected guardian authorization is incomplete (%d succeeded, %d pending, %d total)", authorization.SuccessCount, authorization.PendingCount, authorization.TargetCount))
	}
	if state.TargetCount != authorization.TargetCount || state.SuccessCount != authorization.SuccessCount ||
		state.FailureCount != authorization.FailureCount || state.PendingCount != authorization.PendingCount {
		issues = append(issues, "guardian state and protected authorization target counts do not match")
	}
	if state.UpdatedAt == "" || authorization.UpdatedAt == "" || state.UpdatedAt != authorization.UpdatedAt {
		issues = append(issues, "guardian state and protected authorization do not identify the same reconcile")
	}
	if activation.Version != enterpriseHookGuardianActivationVersion ||
		!validEnterpriseHookHex(activation.ReconcileID, 16) ||
		!validEnterpriseHookHex(activation.ManifestSHA256, sha256.Size) {
		issues = append(issues, "protected guardian activation has an invalid identity")
	}
	if activation.UpdatedAt == "" || activation.UpdatedAt != state.UpdatedAt ||
		activation.UpdatedAt != authorization.UpdatedAt {
		issues = append(issues, "protected guardian activation does not identify the legacy record pair")
	}
	if !enterpriseHookGuardianRecordComplete(activation.OK, activation.SuccessCount, activation.FailureCount, activation.PendingCount, activation.TargetCount, excused) {
		issues = append(issues, fmt.Sprintf(
			"protected guardian activation is incomplete (%d succeeded, %d pending, %d total)",
			activation.SuccessCount,
			activation.PendingCount,
			activation.TargetCount,
		))
	}
	if activation.TargetCount != state.TargetCount ||
		activation.SuccessCount != state.SuccessCount ||
		activation.FailureCount != state.FailureCount ||
		activation.PendingCount != state.PendingCount {
		issues = append(issues, "protected guardian activation target counts do not match")
	}
	if expected := strings.TrimSpace(expectedManifest); expected != "" && !sameEnterpriseHookPath(state.Manifest, expected) {
		issues = append(issues, fmt.Sprintf("guardian state records manifest %s, expected %s", state.Manifest, expected))
	}
	if expected := strings.TrimSpace(expectedManifest); expected != "" &&
		!sameEnterpriseHookPath(activation.Manifest, expected) {
		issues = append(issues, fmt.Sprintf("guardian activation records manifest %s, expected %s", activation.Manifest, expected))
	}
	if expected := strings.TrimSpace(expectedManifestSHA256); expected != "" && activation.ManifestSHA256 != expected {
		issues = append(issues, fmt.Sprintf("guardian activation records manifest SHA-256 %s, expected %s", activation.ManifestSHA256, expected))
	}
	if (state.OK && authorization.OK) || excused > 0 {
		protectedRows := enterpriseHookProtectedReconcileRows(state.Results)
		authorizationTargets, activationTargets := authorization.ProtectedTargets, activation.ProtectedTargets
		if excused > 0 {
			// Both records carry forward the excused failed targets' prior
			// rows; every other target must still match exactly.
			authorizationTargets = enterpriseHookTargetsExceptFailed(authorizationTargets, state.Results)
			activationTargets = enterpriseHookTargetsExceptFailed(activationTargets, state.Results)
		}
		issues = append(
			issues,
			compareEnterpriseHookProtectedTargetSets(protectedRows, authorizationTargets, "authorization")...,
		)
		issues = append(
			issues,
			compareEnterpriseHookProtectedTargetSets(protectedRows, activationTargets, "activation")...,
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
				issues = append(issues, fmt.Sprintf("protected authorization does not cover %s", enterpriseHookTargetIssueLabel(row)))
			}
		}
	}
	return issues
}

func enterpriseHookProtectedReconcileRows(rows []enterpriseHookReconcileRow) []enterpriseHookReconcileRow {
	protected := make([]enterpriseHookReconcileRow, 0, len(rows))
	for _, row := range rows {
		if row.OK {
			protected = append(protected, row)
		}
	}
	return protected
}

// enterpriseHookTargetsExceptFailed is a protected record's targets without
// those that failed in results.
func enterpriseHookTargetsExceptFailed(protected, results []enterpriseHookReconcileRow) []enterpriseHookReconcileRow {
	failed := map[string]struct{}{}
	for _, row := range results {
		if key := enterpriseHookProtectedTargetKey(row); key != "" && !row.OK && !row.Pending {
			failed[key] = struct{}{}
		}
	}
	kept := make([]enterpriseHookReconcileRow, 0, len(protected))
	for _, row := range protected {
		if _, excused := failed[enterpriseHookProtectedTargetKey(row)]; !excused {
			kept = append(kept, row)
		}
	}
	return kept
}

// compareEnterpriseHookProtectedTargetSets diffs the reconcile-time target
// set against a protected record. `record` names the record whose drift is
// being reported (for example "authorization" or "activation") so operators
// can triage the correct file when the sets diverge.
func compareEnterpriseHookProtectedTargetSets(
	expected, actual []enterpriseHookReconcileRow,
	record string,
) []string {
	expectedByKey := make(map[string]enterpriseHookReconcileRow, len(expected))
	actualByKey := make(map[string]enterpriseHookReconcileRow, len(actual))
	var issues []string
	for _, row := range expected {
		key := enterpriseHookProtectedTargetKey(row)
		if key == "" {
			issues = append(issues, fmt.Sprintf("current enabled target is incomplete: %s", enterpriseHookTargetIssueLabel(row)))
			continue
		}
		if _, duplicate := expectedByKey[key]; duplicate {
			issues = append(issues, fmt.Sprintf("current enabled target is duplicated: %s", enterpriseHookTargetIssueLabel(row)))
			continue
		}
		expectedByKey[key] = row
	}
	for _, row := range actual {
		key := enterpriseHookProtectedTargetKey(row)
		if key == "" {
			issues = append(issues, fmt.Sprintf("protected %s contains an incomplete target: %s", record, enterpriseHookTargetIssueLabel(row)))
			continue
		}
		if _, duplicate := actualByKey[key]; duplicate {
			issues = append(issues, fmt.Sprintf("protected %s contains a duplicate target: %s", record, enterpriseHookTargetIssueLabel(row)))
			continue
		}
		actualByKey[key] = row
	}
	for key, row := range expectedByKey {
		if _, covered := actualByKey[key]; !covered {
			issues = append(issues, fmt.Sprintf("protected %s does not cover %s", record, enterpriseHookTargetIssueLabel(row)))
		}
	}
	for key, row := range actualByKey {
		if _, enabled := expectedByKey[key]; !enabled {
			issues = append(issues, fmt.Sprintf("protected %s contains extra or stale target %s", record, enterpriseHookTargetIssueLabel(row)))
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

// enterpriseHookTargetIssueLabel names a target in a failure or drift
// message. On Windows a guardian row carries only the account's SID, so the
// message names the account as "user (SID)", as the guardian notices do
// (GAP-2290); elsewhere it is enterpriseHookTargetLabel. Only rendered: keys
// and matching use the SID.
func enterpriseHookTargetIssueLabel(row enterpriseHookReconcileRow) string {
	if strings.TrimSpace(row.SID) == "" {
		return enterpriseHookTargetLabel(row)
	}
	return strings.TrimSpace(row.Connector) + "@" + enterpriseHookTargetIssueAccount(row)
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
	Manifest string
	Rows     []enterpriseHookReconcileRow
	Failures int
	Pending  int
	// Excused are the failed rows of a confirmed removed account and those
	// waiting for their signed-out account's next sign-in, when every failed
	// row of the last guardian reconcile qualifies
	// (enterpriseHookExcusedFailures). They count in Failures, so the
	// dispositions still match the guardian's records, and verify reports
	// them as warnings, as status does.
	Excused []enterpriseHookReconcileRow
	// AwaitingSignIn maps the key of each excused row that waits for a
	// sign-in to the error of the guardian row that records the wait.
	AwaitingSignIn map[string]string
	// RecordedProtected names the excused signed-out Hermes rows
	// (enterpriseHookHermesSignedOutRow) the guardian last recorded as
	// protected; the protected records are compared with them as protected.
	RecordedProtected map[string]bool
	AuthorizationErr  error
}

// enterpriseHookVerifyExcusedNote is the note of one of run.Excused: for a
// row that waits for its signed-out account's next sign-in, why, from the
// guardian row that records the wait.
func enterpriseHookVerifyExcusedNote(run enterpriseHookVerifyRun, row enterpriseHookReconcileRow) string {
	key := enterpriseHookProtectedTargetKey(row)
	if guardianErr, ok := run.AwaitingSignIn[key]; ok && key != "" {
		return " (pending until the account signs in: " + enterpriseHookAwaitingSignInCause(guardianErr) + ")"
	}
	return enterpriseHookRemovedAccountNote
}

// enterpriseHookVerifyRowExcused reports whether row is one of run.Excused.
func enterpriseHookVerifyRowExcused(run enterpriseHookVerifyRun, row enterpriseHookReconcileRow) bool {
	key := enterpriseHookProtectedTargetKey(row)
	for _, excused := range run.Excused {
		if key != "" && enterpriseHookProtectedTargetKey(excused) == key {
			return true
		}
	}
	return false
}

// enterpriseHookVerifyAwaitingSignIn reports a failed verify row that the
// last guardian reconcile recorded as waiting for its account's next
// sign-in, while that account is still signed out. Once the account signs
// in, the row fails verify until the guardian has repaired it.
func enterpriseHookVerifyAwaitingSignIn(
	awaiting map[string]string,
	target enterprisehooks.ManifestTarget,
	row enterpriseHookReconcileRow,
) bool {
	guardianErr, ok := awaiting[enterpriseHookProtectedTargetKey(row)]
	if !ok || !target.IsDeferred() {
		return false
	}
	if enterpriseHookHermesSignedOutApplies() && strings.EqualFold(strings.TrimSpace(row.Connector), "hermes") &&
		enterpriseHookHermesHomeWaitRecorded(enterpriseHookReconcileRow{Error: guardianErr}, true) {
		// That wait excused only an unreadable Hermes home, which
		// enterpriseHookHermesSignedOutRow already reports. A Hermes target
		// whose home now reads and whose hook fails is a failure, signed in
		// or not, until the guardian classifies it again (GAP-1433).
		return false
	}
	available, err := enterpriseHookReconcileSessionAvailable(target)
	if err != nil && enterpriseHookSessionCheckNotLocalSystem(err) {
		// Setup's own verify, and an administrator's verify or signed
		// bundle apply, run as the elevated administrator, which cannot
		// query another account's session. On Secure Client the guardian's
		// fresh protected record of the wait stands, as status reads it:
		// the LocalSystem guardian proved the session absent when it wrote
		// the row, and repairs the target once the account signs in.
		if enterpriseHookReconcileSecureClient() {
			return true
		}
		// Standalone reads the session list instead, as the Hermes wait
		// does: refusing every wait there failed verify 1603, and the
		// hot-config proof of a signed bundle, after a hook fail mode change
		// while an enrolled account was signed out or disconnected
		// (GAP-2044, GAP-1719).
		noSession, listErr := enterpriseHookTargetHasNoSession(target)
		return listErr == nil && noSession
	}
	return err == nil && !available
}

var enterpriseHookDeferredPendingStateVerifier = enterprisehooks.RequireWindowsEnterpriseDeferredTargetPending

func enterpriseHookDeferredPendingAfterSessionError(
	target enterprisehooks.ManifestTarget,
	previouslyProtected bool,
	err error,
) (bool, error) {
	if err == nil || !target.IsDeferred() || previouslyProtected ||
		!enterprisehooks.IsWindowsTargetSessionUnavailable(err) {
		return false, err
	}
	available, checkErr := enterpriseHookDeferredTargetSessionAvailable(target)
	if checkErr != nil {
		return false, checkErr
	}
	if available {
		// The session changed between the mutating operation and the bounded
		// recheck. Preserve the original failure so this cycle cannot claim a
		// pending state from a stale observation; the next cycle retries.
		return false, err
	}
	return true, nil
}

const enterpriseHookVerifyGenerationAttempts = 5

var enterpriseHookVerifyGenerationRetryDelay = 50 * time.Millisecond

// enterpriseHookVerifyGenerationSnapshot is the authenticated identity of all
// connector selectors used by one Verify pass. The selectors contain no token
// material; their CAS values bind the complete machine-protected bytes for the
// connector, including every enrolled SID and immutable generation ID.
type enterpriseHookVerifyGenerationSnapshot struct {
	Claude enterprisehooks.WindowsManagedRuntimeSelectorCAS
	Codex  enterprisehooks.WindowsManagedRuntimeSelectorCAS
	Cursor enterprisehooks.WindowsManagedRuntimeSelectorCAS
}

type enterpriseHookVerifyGenerationCapture func() (
	enterpriseHookVerifyGenerationSnapshot,
	bool,
	error,
)

var enterpriseHookVerifyCaptureGeneration enterpriseHookVerifyGenerationCapture = captureEnterpriseHookVerifyGeneration

func runEnterpriseHooksVerify(cmd *cobra.Command, _ []string) error {
	return runEnterpriseHooksVerifyWithScope(cmd, false)
}

func runEnterpriseHooksReadiness(cmd *cobra.Command, _ []string) error {
	if cfg == nil || !cfg.StandaloneEnterprise() ||
		(runtime.GOOS != "windows" && runtime.GOOS != "linux" && runtime.GOOS != "darwin") {
		platform := "Unix"
		if runtime.GOOS == "windows" {
			platform = "Windows"
		}
		return fmt.Errorf("enterprise hooks readiness is available only for managed standalone %s Setup", platform)
	}
	return runEnterpriseHooksVerifyWithScope(cmd, true)
}

func runEnterpriseHooksVerifyWithScope(cmd *cobra.Command, registrationOnly bool) error {
	var run enterpriseHookVerifyRun
	var err error
	var notes *enterpriseHookNoteSet
	defer enterpriseHookVerifyRunScope()()
	if registrationOnly {
		notes = &enterpriseHookNoteSet{}
		enterpriseHookReadinessNotes.Store(notes)
		run, err = runEnterpriseHookRegistrationOnce(cmd.Context())
		enterpriseHookReadinessNotes.Store(nil)
	} else {
		run, err = runEnterpriseHookVerifyOnce(cmd.Context())
	}
	if err != nil {
		return err
	}
	failures := run.Failures - len(run.Excused)
	ok := failures == 0 && run.AuthorizationErr == nil
	if enterpriseHookJSON {
		payload := map[string]any{
			"ok":                               ok,
			"manifest":                         run.Manifest,
			"results":                          run.Rows,
			"claude_effective_policy_verified": enterpriseHooksClaudeEffectivePolicyVerified(run.Rows),
		}
		if registrationOnly {
			payload["scope"] = "machine_hook_registration"
			for _, row := range run.Rows {
				if strings.EqualFold(row.Connector, "hermes") {
					payload["hermes_session_coverage"] = "not_covered"
					break
				}
			}
		}
		if run.AuthorizationErr != nil {
			payload["authorization_error"] = run.AuthorizationErr.Error()
		}
		if warnings := enterpriseHookVerifyWarnings(run, notes); len(warnings) != 0 {
			payload["warnings"] = warnings
		}
		if len(run.Excused) != 0 {
			// The excused targets by SID and connector, so a caller that waits
			// for the guardian (a signed bundle's hook proof) treats them as
			// verify does instead of waiting for a sign-in (review loop 2).
			excused := make([]map[string]string, 0, len(run.Excused))
			for _, row := range run.Excused {
				excused = append(excused, map[string]string{"sid": row.SID, "connector": row.Connector})
			}
			payload["excused"] = excused
		}
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(payload); err != nil {
			return err
		}
		if !ok {
			if registrationOnly {
				return fmt.Errorf("enterprise hooks readiness failed")
			}
			return fmt.Errorf("enterprise hooks verify failed")
		}
		return nil
	}
	verb := "verified"
	if registrationOnly {
		verb = "registered"
	}
	for _, row := range run.Rows {
		if row.OK {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s %s%s\n", Style("✓", "fg=green", "bold"), enterpriseHookTargetLabel(row), verb, enterpriseHookAgentVersionNote(row))
		} else if row.Pending {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s pending an exact active Windows session\n", Style("•", "fg=yellow", "bold"), enterpriseHookTargetLabel(row))
		} else if enterpriseHookVerifyRowExcused(run, row) {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s: %s%s\n", Style("•", "fg=yellow", "bold"), enterpriseHookTargetLabel(row), row.Error, enterpriseHookVerifyExcusedNote(run, row))
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s %s: %s\n", Style("✗", "fg=red", "bold"), enterpriseHookTargetLabel(row), row.Error)
		}
	}
	for _, note := range notes.list() {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s %s\n", Style("•", "fg=yellow", "bold"), note)
	}
	if run.AuthorizationErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s protected authorization: %s\n", Style("✗", "fg=red", "bold"), run.AuthorizationErr)
	}
	if !ok {
		if registrationOnly {
			return fmt.Errorf("enterprise hooks readiness failed for %d target(s)", failures)
		}
		return fmt.Errorf("enterprise hooks verify failed for %d target(s)", failures)
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
	return runEnterpriseHookVerifyGenerationConsistent(
		ctx,
		enterpriseHookVerifyCaptureGeneration,
		enterpriseHookVerifyGenerationAttempts,
		enterpriseHookVerifyGenerationRetryDelay,
		runEnterpriseHookVerifyAttempt,
	)
}

func runEnterpriseHookRegistrationOnce(ctx context.Context) (enterpriseHookVerifyRun, error) {
	return runEnterpriseHookVerifyGenerationConsistent(
		ctx,
		enterpriseHookVerifyCaptureGeneration,
		enterpriseHookVerifyGenerationAttempts,
		enterpriseHookVerifyGenerationRetryDelay,
		runEnterpriseHookRegistrationAttempt,
	)
}

func runEnterpriseHookRegistrationAttempt(ctx context.Context) (enterpriseHookVerifyRun, error) {
	return runEnterpriseHookVerifyAttemptWithScope(ctx, true)
}

func captureEnterpriseHookVerifyGeneration() (
	enterpriseHookVerifyGenerationSnapshot,
	bool,
	error,
) {
	var generation enterpriseHookVerifyGenerationSnapshot
	if runtime.GOOS != "windows" || cfg == nil ||
		!managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return generation, false, nil
	}
	selectors := [...]struct {
		name string
		set  func(enterprisehooks.WindowsManagedRuntimeSelectorCAS)
	}{
		{name: "claudecode", set: func(cas enterprisehooks.WindowsManagedRuntimeSelectorCAS) {
			generation.Claude = cas
		}},
		{name: "codex", set: func(cas enterprisehooks.WindowsManagedRuntimeSelectorCAS) {
			generation.Codex = cas
		}},
		{name: "cursor", set: func(cas enterprisehooks.WindowsManagedRuntimeSelectorCAS) {
			generation.Cursor = cas
		}},
	}
	for _, selector := range selectors {
		cas, err := enterprisehooks.ReadWindowsManagedRuntimeSelectorCAS(selector.name)
		if err != nil {
			return generation, true, fmt.Errorf(
				"capture %s managed runtime selector for generation-consistent verify: %w",
				selector.name,
				err,
			)
		}
		selector.set(cas)
	}
	return generation, true, nil
}

// runEnterpriseHookVerifyGenerationConsistent makes one complete Verify pass
// optimistic over the three protected selector files. A Guardian publication
// may replace several target-owned files before it atomically selects the new
// immutable bundle, so a failed pass is retried even when its first selector
// re-read is unchanged; a genuine stable defect still fails closed after the
// strict attempt bound. Successful results are accepted only when the full
// selector vector is byte-identity-equivalent before and after every target.
func runEnterpriseHookVerifyGenerationConsistent(
	ctx context.Context,
	capture enterpriseHookVerifyGenerationCapture,
	attempts int,
	retryDelay time.Duration,
	verify func(context.Context) (enterpriseHookVerifyRun, error),
) (enterpriseHookVerifyRun, error) {
	var last enterpriseHookVerifyRun
	if attempts <= 0 {
		return last, errors.New("enterprise hooks verify: generation attempt bound is invalid")
	}
	for attempt := 0; attempt < attempts; attempt++ {
		before, enabled, err := capture()
		if err != nil {
			return last, err
		}
		if !enabled {
			return verify(ctx)
		}

		last, err = verify(ctx)
		after, afterEnabled, captureErr := capture()
		if captureErr != nil {
			return last, captureErr
		}
		if !afterEnabled {
			return last, errors.New(
				"enterprise hooks verify: managed runtime selector capture became unavailable",
			)
		}
		stable := before == after
		if err != nil && stable {
			// Manifest/configuration trust errors are outside the mutable target
			// publication window. Preserve their original fail-closed result.
			return last, err
		}
		// A deleted account's excused rows fail every pass until the
		// enumerator drops them; retrying cannot change them.
		failed := err != nil || last.Failures != len(last.Excused) || last.AuthorizationErr != nil
		if stable && !failed {
			return last, nil
		}
		if attempt == attempts-1 {
			if stable {
				return last, err
			}
			return last, fmt.Errorf(
				"enterprise hooks verify: protected managed runtime generation changed during %d bounded attempts",
				attempts,
			)
		}
		if retryDelay <= 0 {
			continue
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return last, ctx.Err()
		case <-timer.C:
		}
	}
	return last, errors.New("enterprise hooks verify: generation attempt bound exhausted")
}

func runEnterpriseHookVerifyAttempt(ctx context.Context) (enterpriseHookVerifyRun, error) {
	return runEnterpriseHookVerifyAttemptWithScope(ctx, false)
}

var enterpriseHookLivePublicVerifier = enterprisehooks.Verify
var enterpriseHookLiveRegistrationVerifier = enterpriseHookGuardianVerify

func enterpriseHookLiveTargetVerifier(ctx context.Context, opts enterprisehooks.InstallOptions, registrationOnly bool) (enterprisehooks.InstallResult, error) {
	if registrationOnly && strings.EqualFold(strings.TrimSpace(opts.ConnectorName), "hermes") {
		return enterpriseHookLiveRegistrationVerifier(ctx, opts)
	}
	return enterpriseHookLivePublicVerifier(ctx, opts)
}

func runEnterpriseHookVerifyAttemptWithScope(ctx context.Context, registrationOnly bool) (enterpriseHookVerifyRun, error) {
	run := enterpriseHookVerifyRun{Manifest: enterpriseHookManifest}
	if cfg == nil {
		return run, fmt.Errorf("enterprise hooks verify: config is not loaded")
	}
	if enterpriseHooksStandaloneUnixActive() {
		return runEnterpriseHookVerifyAttemptStandaloneUnix(ctx, registrationOnly)
	}
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if err := enterpriseHookManifestFileTrustCheck(enterpriseHookManifest); err != nil {
			return run, fmt.Errorf("enterprise hooks verify: manifest trust check failed: %w", err)
		}
		if err := validateEnterpriseHookManagedRuntime(); err != nil {
			return run, err
		}
	}
	manifest, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(enterpriseHookManifest)
	if err != nil {
		return run, err
	}
	records := loadEnterpriseHookGuardianRecords(cfg.DataDir)
	authorization, exists, authorizationErr := records.Authorization, records.AuthorizationExists, records.AuthorizationErr
	activation, activationExists, activationErr := records.Activation, records.ActivationExists, records.ActivationErr
	guardianState, guardianStateExists, guardianStateErr := records.State, records.StateExists, records.StateErr
	// The rows of a deleted account whose profile folder was removed fail
	// every reconcile until the enumerator drops them, and those an earlier
	// release protected fail until their signed-out account signs in again;
	// verify accepts exactly those failures, as status does.
	excused := 0
	awaitingSignIn := map[string]string{}
	// The guardian's last row of each target, for a Hermes target whose
	// account is signed out (enterpriseHookHermesSignedOutRow).
	recorded := map[string]enterpriseHookReconcileRow{}
	if guardianStateErr == nil && guardianStateExists {
		for _, row := range guardianState.Results {
			if key := enterpriseHookProtectedTargetKey(row); key != "" {
				recorded[key] = row
			}
		}
		removed, awaiting := enterpriseHookExcusedFailures(guardianState)
		excused = removed + awaiting
		for _, row := range guardianState.Results {
			if awaiting > 0 && enterpriseHookAwaitingSignInRow(row) {
				awaitingSignIn[enterpriseHookProtectedTargetKey(row)] = row.Error
			}
		}
	}
	// Registration readiness scopes a target's own guardian failure to that
	// target: one target's failure never fails another target's proof (a
	// hot-config undo or Setup readiness of the rest).
	recordExcused := excused
	partialRegistration := registrationOnly && excused == 0 && enterpriseHookPartialGuardianRecord(authorization, activation)
	if partialRegistration {
		recordExcused = authorization.FailureCount
	}
	if authorizationErr != nil {
		run.AuthorizationErr = authorizationErr
	} else if !exists {
		run.AuthorizationErr = fmt.Errorf("protected hook guardian authorization is missing")
	} else if !enterpriseHookGuardianRecordComplete(authorization.OK, authorization.SuccessCount, authorization.FailureCount,
		authorization.PendingCount, authorization.TargetCount, recordExcused) {
		run.AuthorizationErr = fmt.Errorf("protected hook guardian authorization is incomplete (%d succeeded, %d pending, %d total)", authorization.SuccessCount, authorization.PendingCount, authorization.TargetCount)
	} else if freshnessErr := managed.ValidateHookGuardianFreshness(authorization.UpdatedAt, time.Now()); freshnessErr != nil {
		run.AuthorizationErr = fmt.Errorf("protected hook guardian authorization is not fresh: %w", freshnessErr)
	} else if activationErr != nil {
		run.AuthorizationErr = activationErr
	} else if !activationExists {
		run.AuthorizationErr = fmt.Errorf("protected hook guardian activation is missing")
	} else if (!activation.OK && (recordExcused <= 0 || activation.FailureCount != recordExcused)) ||
		activation.UpdatedAt != authorization.UpdatedAt ||
		activation.ManifestSHA256 != manifestSHA256 {
		run.AuthorizationErr = fmt.Errorf("protected hook guardian activation does not cover the current manifest bytes")
	}
	authenticatedPending := map[string]struct{}{}
	if run.AuthorizationErr == nil &&
		(authorization.PendingCount != 0 || activation.PendingCount != 0) {
		if guardianStateErr != nil {
			run.AuthorizationErr = guardianStateErr
		} else if !guardianStateExists {
			run.AuthorizationErr = fmt.Errorf("hook guardian state is missing for deferred pending verification")
		} else {
			authenticatedPending, err = enterpriseHookAuthenticatedPendingTargets(
				manifest,
				guardianState,
				authorization,
				activation,
				enterpriseHookManifest,
				manifestSHA256,
				recordExcused,
			)
			if err != nil {
				run.AuthorizationErr = err
			}
		}
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
	claudeMachineContract := enterpriseHookMachinePolicyContract(manifest)
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
		var previousProtection enterpriseHookPreviousProtection
		if targetErr == nil {
			previousProtection, targetErr = previousEnterpriseHookProtection(
				cfg.DataDir,
				target.User,
				resolved.home,
				resolved.sid,
				target.Connector,
			)
		}
		if targetErr == nil && target.IsDeferred() &&
			!previousProtection.PreviouslyProtected {
			var pending bool
			pending, targetErr = enterpriseHookVerifyAuthenticatedPendingTarget(
				target,
				row,
				authenticatedPending,
			)
			if targetErr == nil && pending {
				row.Pending = true
				run.Pending++
				run.Rows = append(run.Rows, row)
				continue
			}
		}
		token := ""
		otlpToken := ""
		if targetErr == nil {
			token, otlpToken, targetErr = enterpriseHookTargetTokens(cfg.DataDir, target.Connector, resolved.sid, false)
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
				// Standalone Amp and OpenCode only; empty on Secure Client.
				ForeignHookGuardBinary: standaloneForeignHookGuardBinary(target.Connector),
				ManagedHookBinary:      standaloneManagedHookBinary(),
			}
			opts.MachinePolicyContractID = enterpriseHookMachinePolicyContractFor(target.Connector, claudeMachineContract)
			var result enterprisehooks.InstallResult
			result, targetErr = enterpriseHookLiveTargetVerifier(ctx, opts, registrationOnly)
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
		if waiting, ok := enterpriseHookHermesSignedOutRow(target, row, targetErr, recorded); ok {
			// Unobservable, not failed: reported pending until the
			// account signs in (Hermes NOT COVERED), never protected,
			// and compared with the protected records as the guardian
			// last recorded it.
			row.OK, row.Pending, row.Result, row.Error = false, false, nil, waiting
			run.Failures++
			run.Excused = append(run.Excused, row)
			if run.AwaitingSignIn == nil {
				run.AwaitingSignIn = map[string]string{}
			}
			run.AwaitingSignIn[enterpriseHookProtectedTargetKey(row)] = waiting
			if last := recorded[enterpriseHookProtectedTargetKey(row)]; last.OK {
				if run.RecordedProtected == nil {
					run.RecordedProtected = map[string]bool{}
				}
				run.RecordedProtected[enterpriseHookProtectedTargetKey(row)] = true
			}
			run.Rows = append(run.Rows, row)
			continue
		}
		if targetErr != nil {
			row.OK = false
			row.Error = targetErr.Error()
			run.Failures++
			if excused > 0 && enterpriseHookRemovedAccountRow(row) {
				run.Excused = append(run.Excused, row)
			} else if excused > 0 && enterpriseHookVerifyAwaitingSignIn(awaitingSignIn, target, row) {
				run.Excused = append(run.Excused, row)
				if run.AwaitingSignIn == nil {
					run.AwaitingSignIn = map[string]string{}
				}
				run.AwaitingSignIn[enterpriseHookProtectedTargetKey(row)] = awaitingSignIn[enterpriseHookProtectedTargetKey(row)]
			}
		}
		run.Rows = append(run.Rows, row)
	}
	if run.AuthorizationErr == nil && exists && activationExists {
		proof := enterpriseHookRecordedProtectionProof(run)
		if partialRegistration {
			proof = enterpriseHookPartialRegistrationProof(proof)
		}
		if issues := enterpriseHookVerifyDispositionIssues(
			proof,
			authorization,
			activation,
		); len(issues) > 0 {
			run.AuthorizationErr = fmt.Errorf("%s", strings.Join(issues, "; "))
		}
	}
	return run, nil
}

// enterpriseHookHermesSignedOutRow reports a managed standalone Windows
// Hermes target whose account is signed out (GAP-1433): Windows has not
// loaded the registry hive that holds its HERMES_HOME, so the home its Hermes
// reads is unobservable. That is the live verification failing with
// hermespath.ErrAccountSignedOut, or the guardian's last pass recording the
// target as waiting for that reason while live verification now passes (the
// hive comes and goes with other logons; the guardian verifies it again at
// the account's sign-in). It returns the sign-in wait the row reports.
// Every other failure, Secure Client and other connectors are unchanged.
func enterpriseHookHermesSignedOutRow(
	target enterprisehooks.ManifestTarget,
	row enterpriseHookReconcileRow,
	liveErr error,
	recorded map[string]enterpriseHookReconcileRow,
) (string, bool) {
	if !enterpriseHookHermesSignedOutApplies() || !target.IsDeferred() ||
		!strings.EqualFold(strings.TrimSpace(row.Connector), "hermes") {
		return "", false
	}
	last, known := recorded[enterpriseHookProtectedTargetKey(row)]
	lastWaits := enterpriseHookHermesHomeWaitRecorded(last, known)
	switch {
	case liveErr != nil && errors.Is(liveErr, hermespath.ErrAccountSignedOut):
		if lastWaits {
			return strings.TrimSpace(last.Error), true
		}
		return fmt.Sprintf("%s: %s, so Hermes is NOT COVERED for it until the guardian verifies it at its next sign-in "+
			"(verification: %v)", enterpriseHookAwaitingSignInPrefix, enterpriseHookAwaitingSignInHermesHome, liveErr), true
	case liveErr == nil && lastWaits:
		return strings.TrimSpace(last.Error), true
	case liveErr != nil && known && !lastWaits && enterpriseHookAwaitingSignInError(last):
		// The guardian left the target waiting for its sign-in for another
		// cause (an earlier release protected it, GAP-0644). The wait
		// excuses the live failure only with fresh evidence that the
		// account is still signed out: the session check, or, for an
		// elevated administrator, who cannot query another account's
		// session token, the session list read now. Being unable to query
		// the session is never taken as a sign-out (GAP-1433).
		available, err := enterpriseHookReconcileSessionAvailable(target)
		if err == nil && !available {
			return strings.TrimSpace(last.Error), true
		}
		if err != nil && enterpriseHookSessionCheckNotLocalSystem(err) {
			if signedOut, listErr := enterpriseHookTargetHasNoSession(target); listErr == nil && signedOut {
				return strings.TrimSpace(last.Error), true
			}
		}
	}
	return "", false
}

// enterpriseHookHermesHomeWaitRecorded reports a guardian row that waits for
// its account's sign-in only because the account's Hermes home could not be
// read (hermespath.ErrAccountSignedOut).
func enterpriseHookHermesHomeWaitRecorded(last enterpriseHookReconcileRow, known bool) bool {
	return known && enterpriseHookAwaitingSignInError(last) &&
		strings.HasPrefix(strings.TrimSpace(last.Error), enterpriseHookAwaitingSignInPrefix+": "+enterpriseHookAwaitingSignInHermesHome)
}

// enterpriseHookTargetHasNoSession reports, from the Windows session list,
// that no session is signed in as the target's account. It works without
// LocalSystem. Tests replace it.
var enterpriseHookTargetHasNoSession = func(target enterprisehooks.ManifestTarget) (bool, error) {
	return enterprisehooks.WindowsTargetHasNoSession(target.SID)
}

// enterpriseHookHermesSignedOutApplies reports the managed standalone
// Windows deployment, the only one whose Hermes home lives in a registry
// hive. Tests replace it.
var enterpriseHookHermesSignedOutApplies = func() bool {
	return runtime.GOOS == "windows" && cfg != nil && cfg.StandaloneEnterprise() && !cfg.SecureClientIntegration()
}

// enterpriseHookRecordedProtectionProof is run with each signed-out Hermes
// row the guardian last recorded as protected compared as protected: the
// protected records still describe that target, and verify neither claims
// nor drops its protection while its home cannot be observed. The run itself
// is unchanged.
func enterpriseHookRecordedProtectionProof(run enterpriseHookVerifyRun) enterpriseHookVerifyRun {
	if len(run.RecordedProtected) == 0 {
		return run
	}
	proof := run
	proof.Rows = append([]enterpriseHookReconcileRow(nil), run.Rows...)
	proof.Excused = nil
	for i, row := range proof.Rows {
		if run.RecordedProtected[enterpriseHookProtectedTargetKey(row)] {
			proof.Rows[i].OK, proof.Rows[i].Error = true, ""
			proof.Failures--
		}
	}
	for _, row := range run.Excused {
		if !run.RecordedProtected[enterpriseHookProtectedTargetKey(row)] {
			proof.Excused = append(proof.Excused, row)
		}
	}
	return proof
}

func enterpriseHookVerifyAuthenticatedPendingTarget(
	target enterprisehooks.ManifestTarget,
	row enterpriseHookReconcileRow,
	authenticated map[string]struct{},
) (bool, error) {
	if !target.IsDeferred() {
		return false, nil
	}
	if _, ok := authenticated[enterpriseHookProtectedTargetKey(row)]; !ok {
		return false, nil
	}
	if err := enterpriseHookDeferredPendingStateVerifier(target); err != nil {
		return false, err
	}
	return true, nil
}

func enterpriseHookAuthenticatedPendingTargets(
	manifest enterprisehooks.Manifest,
	state enterpriseHookGuardianState,
	authorization enterpriseHookGuardianAuthorization,
	activation enterpriseHookGuardianActivation,
	manifestPath,
	manifestSHA256 string,
	excused int,
) (map[string]struct{}, error) {
	if issues := compareEnterpriseHookGuardianRecordsExcusing(
		state,
		authorization,
		activation,
		manifestPath,
		manifestSHA256,
		excused,
	); len(issues) != 0 {
		return nil, fmt.Errorf(
			"protected Guardian pending proof is invalid: %s",
			strings.Join(issues, "; "),
		)
	}
	expected := make(map[string]enterprisehooks.ManifestTarget)
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{
			SID:       strings.TrimSpace(target.SID),
			Connector: strings.TrimSpace(target.Connector),
		})
		if key == "" {
			return nil, errors.New("protected Guardian pending proof has an incomplete manifest target")
		}
		expected[key] = target
	}
	if len(state.Results) != len(expected) {
		return nil, errors.New("protected Guardian pending proof does not cover the exact enabled manifest")
	}
	pending := make(map[string]struct{}, state.PendingCount)
	seen := make(map[string]struct{}, len(state.Results))
	for _, row := range state.Results {
		key := enterpriseHookProtectedTargetKey(row)
		target, ok := expected[key]
		if !ok {
			return nil, errors.New("protected Guardian pending proof contains a target outside the enabled manifest")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("protected Guardian pending proof contains a duplicate target")
		}
		seen[key] = struct{}{}
		if !strings.EqualFold(strings.TrimSpace(row.SID), strings.TrimSpace(target.SID)) ||
			!strings.EqualFold(strings.TrimSpace(row.Connector), strings.TrimSpace(target.Connector)) ||
			!sameEnterpriseHookPath(row.UserHome, target.UserHome) {
			return nil, errors.New("protected Guardian pending proof target identity differs from the manifest")
		}
		if row.Pending {
			if !target.IsDeferred() || row.OK || row.Result != nil || strings.TrimSpace(row.Error) != "" {
				return nil, errors.New("protected Guardian pending proof contains a noncanonical pending target")
			}
			pending[key] = struct{}{}
		}
	}
	if len(pending) != state.PendingCount || len(pending) != authorization.PendingCount ||
		len(pending) != activation.PendingCount {
		return nil, errors.New("protected Guardian pending proof has inconsistent pending target counts")
	}
	return pending, nil
}

func enterpriseHookVerifyDispositionIssues(
	run enterpriseHookVerifyRun,
	authorization enterpriseHookGuardianAuthorization,
	activation enterpriseHookGuardianActivation,
) []string {
	protected := enterpriseHookProtectedReconcileRows(run.Rows)
	wantTargets := len(run.Rows)
	wantSuccesses := len(protected)
	wantPending := run.Pending
	wantFailures := run.Failures
	authorizationTargets, activationTargets := authorization.ProtectedTargets, activation.ProtectedTargets
	if len(run.Excused) != 0 {
		// Both records carry forward the excused targets' prior rows; every
		// other target must still match exactly.
		authorizationTargets = enterpriseHookTargetsExceptFailed(authorizationTargets, run.Excused)
		activationTargets = enterpriseHookTargetsExceptFailed(activationTargets, run.Excused)
	}
	var issues []string
	if authorization.TargetCount != wantTargets ||
		authorization.SuccessCount != wantSuccesses ||
		authorization.PendingCount != wantPending ||
		authorization.FailureCount != wantFailures {
		issues = append(issues, fmt.Sprintf(
			"protected authorization target dispositions do not match current verification (got %d succeeded, %d pending, %d failed, %d total; want %d succeeded, %d pending, %d failed, %d total)",
			authorization.SuccessCount,
			authorization.PendingCount,
			authorization.FailureCount,
			authorization.TargetCount,
			wantSuccesses,
			wantPending,
			wantFailures,
			wantTargets,
		))
	}
	if activation.TargetCount != wantTargets ||
		activation.SuccessCount != wantSuccesses ||
		activation.PendingCount != wantPending ||
		activation.FailureCount != wantFailures {
		issues = append(issues, fmt.Sprintf(
			"protected activation target dispositions do not match current verification (got %d succeeded, %d pending, %d failed, %d total; want %d succeeded, %d pending, %d failed, %d total)",
			activation.SuccessCount,
			activation.PendingCount,
			activation.FailureCount,
			activation.TargetCount,
			wantSuccesses,
			wantPending,
			wantFailures,
			wantTargets,
		))
	}
	issues = append(
		issues,
		compareEnterpriseHookProtectedTargetSets(
			protected,
			authorizationTargets,
			"authorization",
		)...,
	)
	issues = append(
		issues,
		compareEnterpriseHookProtectedTargetSets(
			protected,
			activationTargets,
			"activation",
		)...,
	)
	sort.Strings(issues)
	return issues
}

func runEnterpriseHookReconcileOnce(ctx context.Context) (enterpriseHookReconcileRun, error) {
	run := enterpriseHookReconcileRun{Manifest: enterpriseHookManifest}
	if cfg == nil {
		return run, fmt.Errorf("enterprise hooks reconcile: config is not loaded")
	}
	if enterpriseHooksStandaloneUnixActive() {
		started := time.Now()
		run, err := runEnterpriseHookReconcileOnceStandaloneUnix(ctx)
		if err == nil {
			// A restore that is not recorded is not named by status: report
			// it and retry with the repair backoff (GAP-0626).
			if restoreErr := recordEnterpriseHookStandaloneUnixRestores(os.Stderr, cfg.DataDir, started, run); restoreErr != nil && run.StateErr == nil {
				run.StateErr = fmt.Errorf("record the restored targets: %w", restoreErr)
			}
		}
		return run, err
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		return run, err
	}
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if err := enterpriseHookManifestFileTrustCheck(enterpriseHookManifest); err != nil {
			return run, fmt.Errorf("enterprise hooks reconcile: manifest trust check failed: %w", err)
		}
		if err := validateEnterpriseHookManagedRuntime(); err != nil {
			return run, err
		}
	}
	manifest, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(enterpriseHookManifest)
	if err != nil {
		return run, err
	}
	run.ManifestSHA256 = manifestSHA256
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
	if err := enterpriseHookReconcileSyncEnrollments(manifest, apiAddr, false); err != nil {
		return run, fmt.Errorf(
			"enterprise hooks reconcile: revoke stale protected enrollments: %w",
			err,
		)
	}
	// Remove DefenseClaw's own per-user registrations for revoked users (as
	// each user), and record the cleanups of signed-out users, before this
	// run's state publication drops the revoked rows from the ledger.
	if err := enterpriseHookStandalonePlatformRevokeUsers(ctx, os.Stderr, manifest); err != nil {
		return run, fmt.Errorf(
			"enterprise hooks reconcile: record revoked per-user registrations: %w",
			err,
		)
	}
	registry := newEnterpriseHooksConnectorRegistry()
	enterpriseHookStandalonePlatformPrepare(os.Stderr)

	rows := make([]enterpriseHookReconcileRow, 0, len(manifest.Targets))
	failures := 0
	// awaitingSignIn counts the failures that wait for their signed-out
	// account's next sign-in (errEnterpriseHookAwaitingSignIn).
	awaitingSignIn := 0
	pending := 0
	repairs := 0
	var restored []enterpriseHookGuardianRestore
	var notices []enterpriseHookGuardianNotice
	pendingTargets := make([]enterprisehooks.ManifestTarget, 0)
	watchDirs := map[string]struct{}{}
	exclusiveFiles := map[string]struct{}{}
	sharedFiles := map[string]struct{}{}
	claudeMachineContract := enterpriseHookMachinePolicyContract(manifest)
	// The targets that verified in a pass a filesystem event armed, checked
	// again over one shared window after the loop (GAP-1825).
	recheckWindow := enterpriseHookReconcileRecheckWindow
	var rechecks []enterpriseHookReconcileRecheck
	var recheckedAt []time.Time
	for index, target := range manifest.Targets {
		enterpriseHookStartup.target(os.Stderr, index, len(manifest.Targets))
		if !target.IsEnabled() {
			continue
		}
		recheck := false
		var recheckOpts enterprisehooks.InstallOptions
		row := enterpriseHookReconcileRow{
			User:      strings.TrimSpace(target.User),
			UserHome:  strings.TrimSpace(target.UserHome),
			SID:       strings.TrimSpace(target.SID),
			Connector: strings.TrimSpace(target.Connector),
		}
		token := ""
		otlpToken := ""
		var previousProtection enterpriseHookPreviousProtection
		resolved, err := resolveEnterpriseHookTargetValues(target.User, target.UserHome, intPtrValue(target.UID), intPtrValue(target.GID), target.SID, target.DataDir)
		if err == nil {
			row.SID = strings.TrimSpace(resolved.sid)
			row.UserHome = strings.TrimSpace(resolved.home)
			var authorizationErr error
			previousProtection, authorizationErr = previousEnterpriseHookProtection(
				cfg.DataDir,
				target.User,
				resolved.home,
				resolved.sid,
				target.Connector,
			)
			if authorizationErr != nil {
				err = authorizationErr
			}
		}
		if err == nil && target.IsDeferred() &&
			!previousProtection.PreviouslyProtected {
			var available bool
			available, err = enterpriseHookReconcileDeferredSessionAvailable(target)
			if err == nil && !available {
				row.Pending = true
				pending++
				pendingTargets = append(pendingTargets, target)
				rows = append(rows, row)
				continue
			}
		}
		if err == nil {
			token, otlpToken, err = enterpriseHookTargetTokens(cfg.DataDir, target.Connector, resolved.sid, true)
		}
		if err == nil {
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
				// Standalone Amp and OpenCode only; empty on Secure Client.
				ForeignHookGuardBinary:  standaloneForeignHookGuardBinary(target.Connector),
				ManagedHookBinary:       standaloneManagedHookBinary(),
				MachinePolicyContractID: enterpriseHookMachinePolicyContractFor(target.Connector, claudeMachineContract),
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
			platformDirs, platformFiles := enterpriseHookPlatformWatchFiles(target.Connector, resolved.home)
			for _, dir := range platformDirs {
				watchDirs[dir] = struct{}{}
			}
			for _, f := range platformFiles {
				exclusiveFiles[f] = struct{}{}
			}
			if err == nil {
				var result enterprisehooks.InstallResult
				var repaired bool
				result, repaired, err = enterpriseHookVerifyOrRepairTarget(
					ctx,
					target,
					opts,
					previousProtection.PreviouslyProtected,
				)
				if err == nil {
					if repaired {
						repairs++
						restored = append(restored, enterpriseHookGuardianRestore{
							SID:        row.SID,
							Connector:  row.Connector,
							RestoredAt: time.Now().UTC().Format(time.RFC3339Nano),
						})
					}
					row.OK = true
					row.UserHome = result.UserHome
					row.Connector = result.Connector
					row.Result = &result
					result.AgentConfig = enterpriseHookAgentConfigNotice(result)
					if result.AgentConfig != "" {
						// A Hermes or Devin config put back or recreated
						// (GAP-0588), or a native OTLP exporter the managed
						// install could not take back (GAP-1839).
						notices = append(notices, enterpriseHookGuardianNotice{User: enterpriseHookNoticeAccount(row), Connector: row.Connector, AgentConfig: result.AgentConfig})
					}
					recheck = recheckWindow > 0 && previousProtection.PreviouslyProtected && !repaired
					recheckOpts = opts
					reconcileEnterpriseForeignHooks(opts)
				}
			}
		}
		var deferredPending bool
		retired := errors.Is(err, errEnterpriseHookProtectionRetired)
		deferredPending, err = enterpriseHookDeferredPendingAfterSessionError(
			target,
			previousProtection.PreviouslyProtected && !retired,
			err,
		)
		if deferredPending {
			row.Pending = true
			// A retired target is not protected now: its prior protected
			// row must not be carried forward into the authorization.
			row.RevokeProtection = retired
			pending++
			pendingTargets = append(pendingTargets, target)
			rows = append(rows, row)
			continue
		}
		if err != nil {
			failures++
			if errors.Is(err, errEnterpriseHookAwaitingSignIn) {
				awaitingSignIn++
			}
			row.OK = false
			row.Error = err.Error()
		}
		rows = append(rows, row)
		if recheck {
			rechecks = append(rechecks, enterpriseHookReconcileRecheck{row: len(rows) - 1, target: target, opts: recheckOpts})
			recheckedAt = append(recheckedAt, time.Now())
		}
	}
	recheckEnterpriseHookTargetsOverWindow(ctx, recheckWindow, recheckedAt,
		func(index int) error {
			_, err := enterpriseHookReconcileVerifier(ctx, rechecks[index].opts)
			return err
		},
		func(index int, verifyErr error) {
			recheck := rechecks[index]
			row := &rows[recheck.row]
			result, repaired, err := enterpriseHookRepairAfterVerifyFailure(ctx, recheck.target, recheck.opts, verifyErr)
			if err == nil {
				if repaired {
					repairs++
					restored = append(restored, enterpriseHookGuardianRestore{
						SID:        row.SID,
						Connector:  row.Connector,
						RestoredAt: time.Now().UTC().Format(time.RFC3339Nano),
					})
				}
				row.UserHome = result.UserHome
				row.Connector = result.Connector
				row.Result = &result
				if result.AgentConfig != "" {
					notices = append(notices, enterpriseHookGuardianNotice{User: firstNonEmptyString(row.User, row.SID), Connector: row.Connector, AgentConfig: result.AgentConfig})
				}
				return
			}
			row.OK = false
			row.Result = nil
			retired := errors.Is(err, errEnterpriseHookProtectionRetired)
			deferredPending, err := enterpriseHookDeferredPendingAfterSessionError(recheck.target, !retired, err)
			if deferredPending {
				row.Pending = true
				row.RevokeProtection = retired
				pending++
				pendingTargets = append(pendingTargets, recheck.target)
				return
			}
			failures++
			if errors.Is(err, errEnterpriseHookAwaitingSignIn) {
				awaitingSignIn++
			}
			row.Error = err.Error()
		})
	enterpriseHookStartup.target(os.Stderr, len(manifest.Targets), len(manifest.Targets))
	// A restore that is not recorded is not named by status, so the pass
	// reports it and retries instead of waiting for the interval (GAP-0626).
	restoreErr := recordEnterpriseHookGuardianRestores(os.Stderr, cfg.DataDir, rows, restored)
	if runtime.GOOS == "windows" && enterpriseHookGuardianRestoresEnabled() {
		// The standalone Windows guardian; Linux and macOS record theirs
		// in their own reconcile, and Secure Client records none.
		writeEnterpriseHookGuardianNotices(os.Stderr, cfg.DataDir, notices)
	}

	// A target an earlier release protected that waits for its signed-out
	// account (GAP-0644) keeps the SID enrollment that release published, and
	// the exact set covers every enabled target, so such failures alone do
	// not hold back staging new pending targets or publishing the exact set.
	// Without that, one account that never signs in again keeps every new
	// target unenrolled and verify failing. Any other failure blocks both.
	var enrollmentErr error
	if failures == awaitingSignIn {
		enrollmentErr = enterpriseHookReconcileStageDeferredPolicies(
			manifest,
			pendingTargets,
			apiAddr,
		)
		if enrollmentErr == nil {
			enrollmentErr = enterpriseHookReconcileSyncEnrollments(manifest, apiAddr, true)
		}
	}
	stateErr := writeEnterpriseHookGuardianState(
		cfg.DataDir,
		enterpriseHookManifest,
		manifestSHA256,
		rows,
		failures,
		enrollmentErr == nil,
	)
	if stateErr == nil && enrollmentErr != nil {
		stateErr = fmt.Errorf(
			"publish exact protected enrollment set: %w",
			enrollmentErr,
		)
	}
	if stateErr == nil && restoreErr != nil {
		stateErr = fmt.Errorf("record the restored targets: %w", restoreErr)
	}
	enterpriseHookStandalonePlatformFinish(ctx, os.Stderr, rows, time.Now())
	run.Rows = rows
	run.Failures = failures
	run.Pending = pending
	run.Repairs = repairs
	run.StateErr = stateErr
	run.WatchDirs = sortedEnterpriseHookWatchDirs(watchDirs)
	run.WatchExclusiveFiles = sortedEnterpriseHookWatchDirs(exclusiveFiles)
	run.WatchSharedFiles = sortedEnterpriseHookWatchDirs(sharedFiles)
	return run, nil
}

// enterpriseHookAfterWatchReconcile runs after each successful reconcile of
// the long-running guardian, never the one-shot reconcile command. The
// standalone Unix guardian starts its per-user AI discovery scans here.
var enterpriseHookAfterWatchReconcile = func(context.Context, io.Writer, enterpriseHookReconcileRun) {}

// enterpriseHookBeforeWatchReconcile runs before each reconcile of the
// long-running guardian, also after a reconcile failed. The standalone
// Windows guardian puts a missing hook binary back here: the reconcile
// itself fails on the missing file, so a repair that waited for a
// successful reconcile never ran (GAP-0935).
var enterpriseHookBeforeWatchReconcile = func(io.Writer) {}

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
	enterpriseHookGuardianWatching.Store(true)
	defer enterpriseHookGuardianWatching.Store(false)
	standaloneConfigFingerprint := enterpriseHookStandaloneConfigFingerprint()
	startEnterpriseHookQuarantineRemovals(cmd.Context(), cmd.ErrOrStderr())
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("enterprise hooks watch: create fsnotify watcher: %w", err)
	}
	defer fsw.Close()
	events := newEnterpriseHookWatchPump(fsw.Events, fsw.Errors, enterpriseHookWatchEventBuffer)

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
	// ownedSnapshot is each owned file's fingerprint as the last reconcile
	// left it. A Write or Chmod that the writer policy or the settle window
	// drops still counts when the file no longer matches it.
	ownedSnapshot := map[string]string{}
	// foundSnapshot is each owned file's fingerprint as the last reconcile
	// found it (the snapshot before ownedSnapshot was retaken), so a pass
	// that made and then dropped a file can be told from a change (GAP-0030).
	foundSnapshot := map[string]string{}
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
		enterpriseHookStandaloneConfigRefresh(cmd.ErrOrStderr())
		enterpriseHookBeforeWatchReconcile(cmd.ErrOrStderr())
		run, err := runEnterpriseHookReconcileOnce(cmd.Context())
		if err != nil {
			repairRetryNeeded = true
			return false, err
		}
		enterpriseHookAfterWatchReconcile(cmd.Context(), cmd.ErrOrStderr(), run)
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
		for k := range foundSnapshot {
			delete(foundSnapshot, k)
		}
		for k, v := range ownedSnapshot {
			foundSnapshot[k] = v
		}
		takeEnterpriseHookOwnedSnapshot(ownedSnapshot, exclusiveOwned, sharedOwned, enterpriseHookOwnedFileFingerprint)
		status := "ok"
		if run.Failures > 0 || run.StateErr != nil {
			status = "attention"
		}
		rowsHash := enterpriseHookReconcileRowsHash(run.Rows)
		changed := enterpriseHookReconcileChanged(rowsHash, lastRowsHash, run.Repairs)
		lastRowsHash = rowsHash
		triggerTag := ""
		if reason == "fsnotify" && lastTriggerPath != "" {
			// Attribute the reconcile to the specific fsnotify event
			// that armed the debounce. When a `no_change=true` cycle
			// keeps recurring, this reveals which path is generating
			// the noise so it can be reclassified or filtered.
			triggerTag = fmt.Sprintf(" trigger_path=%q trigger_op=%s", lastTriggerPath, lastTriggerOp)
		}
		writeEnterpriseHookReconcileLog(
			cmd.ErrOrStderr(),
			reason,
			status,
			run,
			len(watched),
			changed,
			triggerTag,
		)
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

	// In managed_enterprise mode, tolerate a missing
	// targets.yaml at startup by fsnotify-waiting for UCB to drop it.
	// Non-managed-enterprise deployments retain the existing hard-exit
	// behaviour (an operator explicitly asked for a manifest that
	// isn't there; loudly refusing is the right thing).
	// The standalone Windows guardian records how far this first reconcile
	// has come, for the Setup coverage wait (GAP-0401).
	enterpriseHookStartup.begin(cmd.ErrOrStderr(), cfg.DataDir)
	_, startupErr := reconcile("startup")
	enterpriseHookStartup.end(cmd.ErrOrStderr())
	if err := startupErr; err != nil {
		if !isMissingManifestErr(err) || cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
			return err
		}
		if waitErr := waitForEnterpriseHookManifestManaged(cmd.Context(), cmd.ErrOrStderr(), fsw, events); waitErr != nil {
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
	// can collapse to overall `ready`.
	writeGuardianStateOrLog(cmd.ErrOrStderr(), guardianstate.StateReady)

	ticker := time.NewTicker(enterpriseHookWatchInterval)
	defer ticker.Stop()
	debounce := time.NewTimer(time.Hour)
	if !debounce.Stop() {
		<-debounce.C
	}
	debouncePending := false
	debounceReason := ""
	// debouncePaths are the paths of the filesystem events of the pending
	// pass; debounceAllPaths says events were dropped or too many changed.
	var debouncePaths []string
	debounceAllPaths := false
	// debounceArmedAt is when the pending debounce was first armed.
	var debounceArmedAt time.Time
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
		debouncePaths, debounceAllPaths = nil, false
	}
	scheduleRepairRetry()
	// Windows standalone: restore the managed OpenCode plugin as soon as its
	// attributes change, without waiting for the interval pass.
	enterpriseHookStandalonePlatformWatch(cmd.Context(), cmd.ErrOrStderr())
	// A local account created or changed (useradd, usermod) gets its
	// identity record within seconds, before its first hook (GAP-2108).
	accountChanges := enterpriseHookAccountDatabaseChanges(cmd.Context())

	for {
		select {
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		case event, ok := <-events.Events:
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
			//     and Rename are real tamper signals; a Write or Chmod
			//     counts only when the file's content or mode is no
			//     longer what the last reconcile left there (an
			//     in-place rewrite of the hooks waited for the interval
			//     pass, GAP-0045).
			//
			// Events on unowned paths (agent session state, sqlite
			// WAL churn, cache writes, workspace snapshots) are
			// silently dropped — no log, no debounce — because they
			// happen continuously and previously dominated the log.
			//
			// Empty maps means we haven't run a reconcile yet (only
			// possible pre-startup); fall through so the startup
			// reconcile flow is unaffected.
			// Write/Chmod events observed inside the post-reconcile
			// settle window are almost always the tail of writes the
			// reconcile itself just made. Create/Remove/Rename must
			// still reconcile because a user can atomically replace a
			// protected path inside the settle window, leaving the
			// destination present just like the guardian's own atomic
			// rename tail.
			actionable := enterpriseHookWatchOwnedEventActionable(event, exclusiveOwned, sharedOwned)
			settling := actionable && enterpriseHookWatchEventInSettleWindow(time.Now(), settleUntil, event.Op)
			// A Write or Chmod dropped by either rule still counts when
			// the owned file no longer holds what the last reconcile left
			// there: an in-place overwrite of the scoped token right after
			// a pass waited for the interval pass (GAP-0044), as did an
			// in-place rewrite of a shared agent config (GAP-0045).
			// A Create, Remove or Rename of an exclusive-writer file in the
			// settle window that left the file as the pass found it and as
			// it left it is the pass's own make-and-drop tail (a backup
			// receipt a failed repair rolled back): it does not arm another
			// pass, so the repair backoff applies (GAP-0030).
			if !settling && actionable && enterpriseHookWatchExclusiveTailUnchanged(time.Now(), settleUntil, event, exclusiveOwned, foundSnapshot, ownedSnapshot, enterpriseHookOwnedFileFingerprint) {
				settling = true
			}
			if (!actionable || settling) &&
				!enterpriseHookWatchOwnedFileChanged(event.Name, exclusiveOwned, sharedOwned, ownedSnapshot, enterpriseHookOwnedFileFingerprint) {
				if settling {
					droppedInSettle++
				}
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
			lastTriggerPath, lastTriggerOp = enterpriseHookWatchNoteTrigger(lastTriggerPath, lastTriggerOp, event)
			debouncePaths, debounceAllPaths = enterpriseHookWatchAddTriggerPath(debouncePaths, debounceAllPaths, event.Name)
			if !debouncePending {
				debounceArmedAt = time.Now()
			}
			resetEnterpriseHookWatchTimer(debounce, enterpriseHookWatchDebounceDelay(time.Now(), debounceArmedAt, enterpriseHookWatchDebounce, enterpriseHookWatchDebounceMaxWait))
			debouncePending = true
			debounceReason = "fsnotify"
		case err, ok := <-events.Errors:
			if !ok {
				if contextErr := cmd.Context().Err(); contextErr != nil {
					return contextErr
				}
				return errors.New("enterprise hooks watch: fsnotify error channel closed unexpectedly")
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] fsnotify error: %s\n", err)
		case <-events.Overflow:
			// Events were dropped while a reconcile ran; reconcile once more
			// so a dropped change is not left to the interval pass.
			if !debouncePending {
				debounceArmedAt = time.Now()
			}
			resetEnterpriseHookWatchTimer(debounce, enterpriseHookWatchDebounceDelay(time.Now(), debounceArmedAt, enterpriseHookWatchDebounce, enterpriseHookWatchDebounceMaxWait))
			debouncePending = true
			debounceAllPaths = true
			if debounceReason == "" {
				debounceReason = "fsnotify"
			}
		case <-debounce.C:
			if debouncePending {
				debouncePending = false
				reason := debounceReason
				debounceReason = ""
				if reason == "" {
					reason = "fsnotify"
				}
				enterpriseHookReconcileRecheckWindow = enterpriseHookWatchRecheckFor(reason)
				enterpriseHookReconcileRecheckPaths, enterpriseHookReconcileRecheckAll = debouncePaths, debounceAllPaths
				debouncePaths, debounceAllPaths = nil, false
				_, err := reconcile(reason)
				enterpriseHookReconcileRecheckWindow = 0
				enterpriseHookReconcileRecheckPaths, enterpriseHookReconcileRecheckAll = nil, false
				if err != nil {
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
		case <-winsession.Logons():
			// A sign-in forwarded by the standalone Windows service host
			// (never fires otherwise) can make a deferred row's exact
			// active session available; reconcile after the same
			// debounce instead of waiting for the interval tick.
			if !debouncePending {
				// A later filesystem event of this pass is bounded from
				// here, not from the start of an earlier burst.
				debounceArmedAt = time.Now()
			}
			resetEnterpriseHookWatchTimer(debounce, enterpriseHookWatchSessionSettle)
			debouncePending = true
			if debounceReason == "" {
				debounceReason = "session sign-in"
			}
		case <-accountChanges:
			// The local account database changed: the next pass lists
			// the new account and spools its identity record, which the
			// gateway (not root) needs to confirm an unnamed gid on an
			// sss-first host; at the interval tick its first hook could
			// come first and be refused (GAP-2108).
			if !debouncePending {
				debounceArmedAt = time.Now()
			}
			resetEnterpriseHookWatchTimer(debounce, enterpriseHookAccountChangeSettle)
			debouncePending = true
			if debounceReason == "" {
				debounceReason = "account database change"
			}
		case <-ticker.C:
			if enterpriseHookStandaloneConfigChanged(standaloneConfigFingerprint, cmd.ErrOrStderr()) {
				return nil
			}
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
	if enterpriseHooksStandaloneUnixActive() {
		writeEnterpriseHookStandaloneGuardianStateOrLog(w, state)
		return
	}
	statePath := guardianstate.PathForStateRoot(filepath.Dir(filepath.Clean(enterpriseHookManifest)))
	if err := guardianstate.WriteState(statePath, state); err != nil {
		fmt.Fprintf(w, "[hook-guardian] warn: could not write %s state file %s: %v\n", state, statePath, err)
	}
}

// waitForEnterpriseHookManifestManaged is the guardian's bounded wait
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
//     collapsing rule reports overall `waiting_for_targets`.
//   - Adds an fsnotify watch on the manifest's parent directory.
//   - Loop: wait for a WRITE/CREATE event on the manifest path OR the
//     poll ticker fires; on either, re-attempt LoadManifest. Success
//     ⇒ return nil (caller resumes normal boot). Missing ⇒ keep
//     waiting.
//   - Hard cap at enterpriseHookTargetsWaitTimeout — return a
//     distinguishable error so the SCM restart cycle picks the
//     guardian back up cleanly (the gateway's config wait does the
//     same).
//
// A non-missing error from a retried LoadManifest (parse failure,
// symlink) is treated as fatal: we did our one bounded wait, an
// operator now dropped a bad file, further recovery belongs to a
// human triage rather than an unbounded wait loop.
func waitForEnterpriseHookManifestManaged(ctx context.Context, w io.Writer, fsw *fsnotify.Watcher, events *enterpriseHookWatchPump) error {
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
	// silently waiting forever. Distinguishable exit, like the
	// gateway's config wait.
	deadline, cancel := context.WithTimeout(ctx, enterpriseHookTargetsWaitTimeout)
	defer cancel()

	// probeShouldReturn classifies a probeManifestPresent result:
	// nil ⇒ manifest loaded, return success. A missing-file error ⇒
	// keep waiting (this is the whole point of the wait loop). Any
	// OTHER error (parse failure, trust-plumbing rejection, symlink
	// refusal, oversized manifest) ⇒ return that error immediately;
	// the wait loop's contract is "wait for a MISSING file", not
	// "silently absorb 24 hours of broken UCB drops".
	probeShouldReturn := func(err error, reason string) (bool, error) {
		if err == nil {
			fmt.Fprintf(w, "[hook-guardian] targets.yaml %s; resuming\n", reason)
			return true, nil
		}
		if isMissingManifestErr(err) {
			return false, nil
		}
		return true, fmt.Errorf("enterprise hooks watch: targets.yaml probe returned non-missing error: %w", err)
	}

	// Try LoadManifest once up front — the manifest may have landed
	// between the failing startup reconcile and this fsnotify.Add
	// call. Without this probe we'd sit for enterpriseHookTargetsWaitPoll
	// waiting for an event that already happened.
	if done, err := probeShouldReturn(probeManifestPresent(manifestPath), "present on entry to wait loop"); done {
		return err
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
		case event := <-events.Events:
			// Only react to writes/creates for the target file; ignore
			// noise for siblings (a stray temp file, chmod on the
			// dir itself).
			if filepath.Clean(event.Name) != manifestPath {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			if done, err := probeShouldReturn(probeManifestPresent(manifestPath), fmt.Sprintf("appeared (%s)", event.Op)); done {
				return err
			}
		case <-events.Overflow:
			if done, err := probeShouldReturn(probeManifestPresent(manifestPath), "present after dropped events"); done {
				return err
			}
		case fswErr := <-events.Errors:
			// fsnotify.Errors is documented to deliver only
			// recoverable errors (queue overflow, watcher-internal
			// signals). Log and keep waiting; the ticker will retry.
			if fswErr != nil {
				fmt.Fprintf(w, "[hook-guardian] fsnotify wait error: %v\n", fswErr)
			}
		case <-poll.C:
			if done, err := probeShouldReturn(probeManifestPresent(manifestPath), "present on poll"); done {
				return err
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

// enterpriseHookWatchExclusiveTailUnchanged reports whether a Create, Remove
// or Rename of an exclusive-writer file, seen before settleUntil, left the
// file exactly as the last reconcile found it (found) and as it left it
// (left). Such an event is that reconcile's own tail: it made the file and
// dropped it again, as a failed repair does when it rolls back the backup
// receipt it just wrote (GAP-0030). A change made by anyone during the pass
// leaves the file unlike what the pass found, and a file with no fingerprint
// in either snapshot is not judged, so both still reconcile. Shared-writer
// files (agent configs) are never judged here.
func enterpriseHookWatchExclusiveTailUnchanged(now, settleUntil time.Time, event fsnotify.Event, exclusiveOwned map[string]struct{}, found, left map[string]string, fingerprint func(string) string) bool {
	if settleUntil.IsZero() || !now.Before(settleUntil) {
		return false
	}
	if event.Op&(fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
		return false
	}
	cleaned := filepath.Clean(event.Name)
	if _, ok := exclusiveOwned[cleaned]; !ok {
		return false
	}
	before, ok := found[cleaned]
	if !ok {
		return false
	}
	after, ok := left[cleaned]
	if !ok || after != before {
		return false
	}
	return fingerprint(cleaned) == after
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

// enterpriseHookReconcileRowLabel names a reconcile row as connector@user,
// connector@home when the row has no user name, or connector@SID when it has
// neither (a Windows target that failed before its profile path resolved).
func enterpriseHookReconcileRowLabel(row enterpriseHookReconcileRow) string {
	label := row.Connector
	if row.User != "" {
		label += "@" + row.User
	} else if row.UserHome != "" {
		label += "@" + row.UserHome
	} else if row.SID != "" {
		label += "@" + row.SID
	}
	return label
}

// enterpriseHookReconcileLogMaxDetail bounds one failure reason in the watch
// log, so a long error cannot flood it.
const enterpriseHookReconcileLogMaxDetail = 1024

// enterpriseHookReconcileLogDetail keeps a log field (a target label or a
// failure reason) on one bounded line. Control characters, which a user name,
// profile path or error text could carry, become spaces first, so a field
// cannot start a new log line or emit terminal escape sequences.
func enterpriseHookReconcileLogDetail(detail string) string {
	detail = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, detail)
	detail = strings.Join(strings.Fields(detail), " ")
	if detail == "" {
		return "no reason recorded"
	}
	if runes := []rune(detail); len(runes) > enterpriseHookReconcileLogMaxDetail {
		detail = string(runes[:enterpriseHookReconcileLogMaxDetail]) + "…"
	}
	return detail
}

// enterpriseHookReconcileChanged treats an authenticated successful repair as
// a change even when the stable row outcome remains OK before and after it.
// Otherwise a restored hook would be mislabeled no_change=true.
func enterpriseHookReconcileChanged(rowsHash, previousRowsHash string, repairs int) bool {
	return repairs > 0 || rowsHash != previousRowsHash
}

func writeEnterpriseHookReconcileLog(
	writer io.Writer,
	reason,
	status string,
	run enterpriseHookReconcileRun,
	watchDirs int,
	changed bool,
	triggerTag string,
) {
	if changed {
		fmt.Fprintf(
			writer,
			"[hook-guardian] reconcile reason=%s status=%s targets=%d pending=%d failures=%d repairs=%d watch_dirs=%d%s\n",
			reason,
			status,
			len(run.Rows),
			run.Pending,
			run.Failures,
			run.Repairs,
			watchDirs,
			triggerTag,
		)
		// The counts alone do not say which target failed or why; a changed
		// outcome names each failing target once. Unchanged reconciles stay a
		// single line, and `enterprise hooks status` repeats the reasons.
		for _, row := range run.Rows {
			if row.OK || row.Pending {
				continue
			}
			fmt.Fprintf(writer, "[hook-guardian] target %s failed: %s\n",
				enterpriseHookReconcileLogDetail(enterpriseHookReconcileRowLabel(row)),
				enterpriseHookReconcileLogDetail(row.Error))
		}
		return
	}
	// Log at DEBUG-ish cadence: one line per no-change reconcile is useful
	// for liveness triage, but it must remain distinguishable from a repair.
	fmt.Fprintf(
		writer,
		"[hook-guardian] reconcile reason=%s status=%s targets=%d pending=%d failures=%d repairs=%d watch_dirs=%d no_change=true%s\n",
		reason,
		status,
		len(run.Rows),
		run.Pending,
		run.Failures,
		run.Repairs,
		watchDirs,
		triggerTag,
	)
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

// enterpriseHookWatchNoteTrigger keeps the path of the first event of a burst
// (the one that armed the debounce) and joins the ops of later events on that
// same path. An in-place overwrite on macOS reports the truncation (Chmod)
// before the Write, so the pass names both, not Chmod alone.
func enterpriseHookWatchNoteTrigger(path string, op fsnotify.Op, event fsnotify.Event) (string, fsnotify.Op) {
	name := filepath.Clean(event.Name)
	if path == "" {
		return name, event.Op
	}
	if path == name {
		return path, op | event.Op
	}
	return path, op
}

// enterpriseHookOwnedFileFingerprint fingerprints an owned file for the
// watch loop and the standalone Unix owned-files record; tests replace it.
var enterpriseHookOwnedFileFingerprint = enterprisehooks.OwnedFileFingerprint

// takeEnterpriseHookOwnedSnapshot replaces snapshot with the fingerprint of
// every owned file as the reconcile that just finished left it.
func takeEnterpriseHookOwnedSnapshot(snapshot map[string]string, exclusiveOwned, sharedOwned map[string]struct{}, fingerprint func(string) string) {
	for path := range snapshot {
		delete(snapshot, path)
	}
	for _, owned := range []map[string]struct{}{exclusiveOwned, sharedOwned} {
		for path := range owned {
			snapshot[path] = fingerprint(path)
		}
	}
}

// enterpriseHookWatchOwnedFileChanged reports whether path is an owned file
// whose fingerprint is no longer the one the last reconcile left (snapshot).
// An owned file without a snapshot entry counts as changed; an unowned path
// never does.
func enterpriseHookWatchOwnedFileChanged(path string, exclusiveOwned, sharedOwned map[string]struct{}, snapshot map[string]string, fingerprint func(string) string) bool {
	cleaned := filepath.Clean(path)
	_, exclusive := exclusiveOwned[cleaned]
	_, shared := sharedOwned[cleaned]
	if !exclusive && !shared {
		return false
	}
	before, ok := snapshot[cleaned]
	return !ok || fingerprint(cleaned) != before
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

// validateEnterpriseHookManagedRuntime gates the hook guardian on a trusted
// managed runtime. It first gives the platform a chance to repair ACL drift
// that another product may have introduced, then requires the ordinary trust
// verdict to pass; a failed repair never substitutes for a passing validation.
func validateEnterpriseHookManagedRuntime() error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	if err := repairEnterpriseHookManagedRuntimePlatform(
		cfg.DataDir,
		os.Getenv(managed.WindowsServiceAccountEnv),
	); err != nil {
		// Preserve the ordinary trust verdict when repair cannot run. This keeps
		// the diagnostic actionable and, importantly, never turns a failed
		// repair into a successful validation. Report the repair cause alongside
		// the verdict: repair runs a validation fast path, so a repair failure
		// almost always means validation fails too, and only the repair error
		// says why the drift could not be corrected.
		if validationErr := managed.ValidateTrustedServiceRuntimeDir(
			cfg.DataDir,
			"hook guardian state data_dir",
			os.Getenv(managed.WindowsServiceAccountEnv),
		); validationErr != nil {
			return fmt.Errorf(
				"enterprise hooks: data_dir trust check failed: %w",
				errors.Join(
					validationErr,
					fmt.Errorf("managed runtime ACL repair failed: %w", err),
				),
			)
		}
		return fmt.Errorf("enterprise hooks: managed runtime ACL repair failed: %w", err)
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
	PendingCount     int                          `json:"pending_count,omitempty"`
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
	PendingCount     int                          `json:"pending_count,omitempty"`
	ProtectedTargets []enterpriseHookReconcileRow `json:"protected_targets"`
}

// enterpriseHookGuardianActivation is a new, separately protected commit
// receipt. Keeping activation fields out of the legacy state/authorization
// pair lets a failed servicing transaction restart the prior strict v1 binary;
// normal activation still requires this exact-manifest receipt.
type enterpriseHookGuardianActivation struct {
	Version          int                          `json:"version"`
	UpdatedAt        string                       `json:"updated_at"`
	ReconcileID      string                       `json:"reconcile_id"`
	Manifest         string                       `json:"manifest"`
	ManifestSHA256   string                       `json:"manifest_sha256"`
	OK               bool                         `json:"ok"`
	TargetCount      int                          `json:"target_count"`
	SuccessCount     int                          `json:"success_count"`
	FailureCount     int                          `json:"failure_count"`
	PendingCount     int                          `json:"pending_count,omitempty"`
	ProtectedTargets []enterpriseHookReconcileRow `json:"protected_targets"`
}

// enterpriseHookGuardianRecords is one read of the three records the
// guardian rewrites on every pass: its state, the protected authorization and
// the activation receipt.
type enterpriseHookGuardianRecords struct {
	State               enterpriseHookGuardianState
	StateExists         bool
	StateErr            error
	Authorization       enterpriseHookGuardianAuthorization
	AuthorizationExists bool
	AuthorizationErr    error
	Activation          enterpriseHookGuardianActivation
	ActivationExists    bool
	ActivationErr       error
}

// midPass reports a read that met a guardian pass in progress: a record the
// guardian was replacing (a sharing violation on Windows), or complete
// records of two passes.
func (r enterpriseHookGuardianRecords) midPass() bool {
	for _, err := range []error{r.StateErr, r.AuthorizationErr, r.ActivationErr} {
		if err != nil && enterpriseHookGuardianRecordBusy(err) {
			return true
		}
	}
	if r.StateErr != nil || r.AuthorizationErr != nil || r.ActivationErr != nil ||
		!r.StateExists || !r.AuthorizationExists || !r.ActivationExists {
		return false
	}
	return r.State.UpdatedAt != r.Authorization.UpdatedAt || r.Activation.UpdatedAt != r.Authorization.UpdatedAt
}

func readEnterpriseHookGuardianRecords(dataDir string) enterpriseHookGuardianRecords {
	var r enterpriseHookGuardianRecords
	r.State, r.StateExists, r.StateErr = loadEnterpriseHookGuardianState(dataDir)
	r.Authorization, r.AuthorizationExists, r.AuthorizationErr = loadEnterpriseHookGuardianAuthorization(dataDir)
	r.Activation, r.ActivationExists, r.ActivationErr = loadEnterpriseHookGuardianActivation(dataDir)
	return r
}

// Seams for tests. The guardian writes its three records within
// milliseconds; 20 reads 100 ms apart outlast a pass by far.
var (
	readEnterpriseHookGuardianRecordsOnce  = readEnterpriseHookGuardianRecords
	enterpriseHookGuardianRecordRetryDelay = 100 * time.Millisecond
)

const enterpriseHookGuardianRecordReads = 20

// loadEnterpriseHookGuardianRecords reads the guardian's records as one
// reconcile. The guardian rewrites them every minute, and a status or verify
// that read in the middle of a pass failed although the guardian was healthy
// (MDM detection on Windows flapped in about one run in eight). Re-read
// briefly until the three name one pass; any other result is returned as
// read.
func loadEnterpriseHookGuardianRecords(dataDir string) enterpriseHookGuardianRecords {
	for read := 1; ; read++ {
		records := readEnterpriseHookGuardianRecordsOnce(dataDir)
		if !records.midPass() || read == enterpriseHookGuardianRecordReads {
			return records
		}
		time.Sleep(enterpriseHookGuardianRecordRetryDelay)
	}
}

func writeEnterpriseHookGuardianState(
	dataDir,
	manifest,
	manifestSHA256 string,
	rows []enterpriseHookReconcileRow,
	failures int,
	complete bool,
) error {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return fmt.Errorf("no data directory configured")
	}
	manifestSHA256 = strings.TrimSpace(manifestSHA256)
	if !validEnterpriseHookHex(manifestSHA256, sha256.Size) {
		return fmt.Errorf("invalid hook guardian manifest SHA-256")
	}
	reconcileIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, reconcileIDBytes); err != nil {
		return fmt.Errorf("generate hook guardian reconcile ID: %w", err)
	}
	reconcileID := hex.EncodeToString(reconcileIDBytes)
	successes := 0
	pending := 0
	for _, row := range rows {
		if row.OK && row.Pending {
			return fmt.Errorf("hook guardian reconcile row cannot be both successful and pending")
		}
		if row.Pending && (row.Result != nil || strings.TrimSpace(row.Error) != "") {
			return fmt.Errorf("hook guardian pending row contains result or error state")
		}
		if row.OK {
			successes++
		}
		if row.Pending {
			pending++
		}
	}
	if successes+pending+failures != len(rows) {
		return fmt.Errorf("hook guardian reconcile rows have inconsistent target dispositions")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	previous, _, err := loadEnterpriseHookGuardianAuthorization(dataDir)
	if err != nil {
		return err
	}
	protected := mergeProtectedEnterpriseHookTargets(previous.ProtectedTargets, rows)
	authorization := enterpriseHookGuardianAuthorization{
		Version:          1,
		UpdatedAt:        now,
		OK:               complete && failures == 0 && successes+pending == len(rows),
		TargetCount:      len(rows),
		SuccessCount:     successes,
		FailureCount:     failures,
		PendingCount:     pending,
		ProtectedTargets: protected,
	}
	authorizationData, err := json.MarshalIndent(authorization, "", "  ")
	if err != nil {
		return err
	}
	authorizationData = append(authorizationData, '\n')
	authorizationDir, err := prepareEnterpriseHookAuthorizationDir(dataDir)
	if err != nil {
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
		OK:           complete && failures == 0 && successes+pending == len(rows),
		TargetCount:  len(rows),
		SuccessCount: successes,
		FailureCount: failures,
		PendingCount: pending,
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

	// The activation receipt is the final commit point. It binds the exact
	// manifest bytes and random reconcile identity to the already-published v1
	// pair without making those rollback-compatible files unreadable to the
	// prior binary.
	activation := enterpriseHookGuardianActivation{
		Version:          enterpriseHookGuardianActivationVersion,
		UpdatedAt:        now,
		ReconcileID:      reconcileID,
		Manifest:         strings.TrimSpace(manifest),
		ManifestSHA256:   manifestSHA256,
		OK:               complete && failures == 0 && successes+pending == len(rows),
		TargetCount:      len(rows),
		SuccessCount:     successes,
		FailureCount:     failures,
		PendingCount:     pending,
		ProtectedTargets: protected,
	}
	activationData, err := json.MarshalIndent(activation, "", "  ")
	if err != nil {
		return err
	}
	activationData = append(activationData, '\n')
	activationPath := filepath.Join(authorizationDir, hookGuardianActivationFile)
	if err := writeEnterpriseHookProtectedFile(activationPath, activationData); err != nil {
		return fmt.Errorf("write %s: %w", activationPath, err)
	}
	if err := os.Chmod(activationPath, 0o640); err != nil {
		return fmt.Errorf("make hook guardian activation readable: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(activationPath); err != nil {
		return fmt.Errorf("set hook guardian activation ownership: %w", err)
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(activationPath); err != nil {
		return err
	}
	return nil
}

// prepareEnterpriseHookAuthorizationDir creates (or re-hardens) the
// protected directory that holds the guardian's records and returns it.
func prepareEnterpriseHookAuthorizationDir(dataDir string) (string, error) {
	authorizationDir, err := hardenEnterpriseHookAuthorizationDir(dataDir)
	if err != nil {
		return "", err
	}
	return authorizationDir, nil
}

// hardenEnterpriseHookAuthorizationDir creates (or re-hardens) the protected
// directory that holds the guardian's records and returns it.
func hardenEnterpriseHookAuthorizationDir(dataDir string) (string, error) {
	authorizationDir := managed.HookGuardianAuthorizationDir(dataDir)
	if info, statErr := os.Lstat(authorizationDir); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("hook guardian authorization path is not a trusted directory: %s", authorizationDir)
		}
		if err := enterpriseHookAuthorizationDirTrustCheck(authorizationDir); err != nil {
			return "", err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect hook guardian authorization directory: %w", statErr)
	}
	if err := os.MkdirAll(authorizationDir, 0o750); err != nil {
		return "", fmt.Errorf("create hook guardian authorization directory: %w", err)
	}
	if err := os.Chmod(authorizationDir, 0o750); err != nil {
		return "", fmt.Errorf("harden hook guardian authorization directory: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(authorizationDir); err != nil {
		return "", fmt.Errorf("set hook guardian authorization directory ownership: %w", err)
	}
	if err := enterpriseHookAuthorizationDirTrustCheck(authorizationDir); err != nil {
		return "", err
	}
	return authorizationDir, nil
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
	if state.TargetCount < 0 || state.SuccessCount < 0 || state.FailureCount < 0 || state.PendingCount < 0 ||
		state.SuccessCount+state.FailureCount+state.PendingCount != state.TargetCount {
		return enterpriseHookGuardianAuthorization{}, true, fmt.Errorf("hook guardian authorization %s has inconsistent target counts", path)
	}
	rows := make([]enterpriseHookReconcileRow, 0, len(state.ProtectedTargets))
	seen := map[string]struct{}{}
	for _, row := range state.ProtectedTargets {
		if !row.OK || row.Pending {
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

func loadEnterpriseHookGuardianActivation(dataDir string) (enterpriseHookGuardianActivation, bool, error) {
	path := filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), hookGuardianActivationFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return enterpriseHookGuardianActivation{}, false, nil
	}
	if err != nil {
		return enterpriseHookGuardianActivation{}, false, fmt.Errorf("inspect hook guardian activation %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return enterpriseHookGuardianActivation{}, true, fmt.Errorf("hook guardian activation is not a regular file: %s", path)
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		return enterpriseHookGuardianActivation{}, true, err
	}
	data, err := readEnterpriseHookBoundedFile(
		path,
		info,
		enterpriseHookGuardianAuthorizationMaxBytes,
		"hook guardian activation",
	)
	if err != nil {
		return enterpriseHookGuardianActivation{}, true, fmt.Errorf("read hook guardian activation %s: %w", path, err)
	}
	var activation enterpriseHookGuardianActivation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&activation); err != nil {
		return enterpriseHookGuardianActivation{}, true, fmt.Errorf("parse hook guardian activation %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return enterpriseHookGuardianActivation{}, true, fmt.Errorf("parse hook guardian activation %s: trailing content", path)
	}
	if activation.Version != enterpriseHookGuardianActivationVersion ||
		!validEnterpriseHookHex(activation.ReconcileID, 16) ||
		!validEnterpriseHookHex(activation.ManifestSHA256, sha256.Size) ||
		strings.TrimSpace(activation.Manifest) == "" ||
		activation.TargetCount < 0 || activation.SuccessCount < 0 || activation.FailureCount < 0 || activation.PendingCount < 0 ||
		activation.SuccessCount+activation.FailureCount+activation.PendingCount != activation.TargetCount {
		return enterpriseHookGuardianActivation{}, true, fmt.Errorf("hook guardian activation %s has an invalid schema", path)
	}
	rows := make([]enterpriseHookReconcileRow, 0, len(activation.ProtectedTargets))
	seen := map[string]struct{}{}
	for _, row := range activation.ProtectedTargets {
		if !row.OK || row.Pending {
			return enterpriseHookGuardianActivation{}, true, fmt.Errorf("hook guardian activation %s contains an unsuccessful protected target", path)
		}
		key := enterpriseHookProtectedTargetKey(row)
		if key == "" {
			return enterpriseHookGuardianActivation{}, true, fmt.Errorf("hook guardian activation %s contains an incomplete protected target", path)
		}
		if _, duplicate := seen[key]; duplicate {
			return enterpriseHookGuardianActivation{}, true, fmt.Errorf("hook guardian activation %s contains duplicate protected target %q", path, key)
		}
		seen[key] = struct{}{}
		rows = append(rows, row)
	}
	activation.ProtectedTargets = rows
	return activation, true, nil
}

func validEnterpriseHookHex(value string, byteLength int) bool {
	if byteLength <= 0 || len(value) != byteLength*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == byteLength
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
	file, err := openEnterpriseHookBoundedFileWithRetry(path, openEnterpriseHookBoundedFile)
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

// A guardian publication can briefly hold a Windows file while replacing it.
// Retry only a sharing/lock violation; every other read and identity failure
// remains immediate and the wait is bounded below one second.
func openEnterpriseHookBoundedFileWithRetry(path string, open func(string) (*os.File, error)) (*os.File, error) {
	const attempts = 10
	for attempt := 1; ; attempt++ {
		file, err := open(path)
		if err == nil || !enterpriseHookGuardianRecordBusy(err) || attempt >= attempts {
			return file, err
		}
		time.Sleep(100 * time.Millisecond)
	}
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
		// A standalone Unix target whose home is pending is not protected
		// right now; its identity binding, not the ledger, keeps its
		// repair rights.
		if row.Pending && enterpriseHooksStandaloneUnixActive() {
			continue
		}
		// A reused or reassigned uid, or a retired Windows target, must not
		// inherit the previous authorization through the carried-forward row.
		if row.RevokeProtection {
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
		if rowSID == "" || sid == "" || !strings.EqualFold(rowSID, sid) {
			return false
		}
		// A SID match alone is not enough on Windows: a stale ProfileList
		// binding must not carry prior authorization to a different home.
		if userHome != "" {
			rowHome := strings.TrimSpace(row.UserHome)
			if rowHome == "" && row.Result != nil {
				rowHome = row.Result.UserHome
			}
			return rowHome != "" && sameEnterpriseHookPath(rowHome, userHome)
		}
		return true
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

var enterpriseHookLookupUser = user.Lookup

func resolveEnterpriseHookTargetValues(userName, userHome string, uid, gid int, sid, dataDir string) (enterpriseHookTarget, error) {
	return resolveEnterpriseHookTargetValuesForPlatform(userName, userHome, uid, gid, sid, dataDir, runtime.GOOS == "windows")
}

func resolveEnterpriseHookTargetValuesForPlatform(userName, userHome string, uid, gid int, sid, dataDir string, windows bool) (enterpriseHookTarget, error) {
	target := enterpriseHookTarget{
		home: strings.TrimSpace(userHome),
		uid:  uid,
		gid:  gid,
		sid:  strings.TrimSpace(sid),
	}
	secureClient := cfg != nil && cfg.SecureClientIntegration()
	if name := strings.TrimSpace(userName); name != "" &&
		!(windows && target.home != "" && secureClient) {
		u, err := enterpriseHookLookupUser(name)
		if err != nil {
			u, err = enterpriseHookStandaloneLookupFallback(name, err)
		}
		if err != nil {
			return target, fmt.Errorf("enterprise hooks: lookup user %q: %w", name, err)
		}
		if windows && !secureClient {
			resolvedSID := strings.TrimSpace(u.Uid)
			if target.sid != "" && !strings.EqualFold(target.sid, resolvedSID) {
				return target, fmt.Errorf("enterprise hooks: --user and --sid name different accounts")
			}
			target.sid = resolvedSID
			if target.home != "" && !secureClient {
				profileHome, err := enterpriseHookSIDProfilePath(target.sid)
				if err != nil {
					return target, fmt.Errorf("enterprise hooks: resolve profile for user %q: %w", name, err)
				}
				if !sameEnterpriseHookPath(profileHome, target.home) {
					return target, fmt.Errorf("enterprise hooks: --user-home does not belong to --user %q", name)
				}
			}
		}
		if target.home == "" {
			target.home = u.HomeDir
		}
		if target.uid < 0 {
			if windows {
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
			if !windows {
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

// enterpriseHookUserScopedTokens returns the hook API and OTLP credentials
// bound to one user identity (a uid on Unix, a SID on Windows), minting the
// per-machine key on first use. The standalone guardian renders these into
// the user's own hook directory and agent configuration instead of the
// connector-scoped credentials every user of a connector would share, so the
// gateway can attribute a TCP request to the user its credential belongs to.
// The OTLP credential is empty for a connector without an OTLP source.
func enterpriseHookUserScopedTokens(dataDir, connectorName, identity string) (string, string, error) {
	return enterpriseHookUserScopedTokensFor(dataDir, connectorName, identity, true)
}

// loadEnterpriseHookUserScopedTokens is enterpriseHookUserScopedTokens for
// verification: it never mints the key.
func loadEnterpriseHookUserScopedTokens(dataDir, connectorName, identity string) (string, string, error) {
	return enterpriseHookUserScopedTokensFor(dataDir, connectorName, identity, false)
}

func enterpriseHookUserScopedTokensFor(dataDir, connectorName, identity string, mint bool) (string, string, error) {
	connectorName = strings.TrimSpace(connectorName)
	if connectorName == "" {
		return "", "", fmt.Errorf("enterprise hooks: connector is required before deriving per-user credentials")
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return "", "", fmt.Errorf("enterprise hooks: config data_dir is required before deriving per-user credentials")
	}
	if _, ok := connector.CanonicalUserScopedIdentity(identity); !ok {
		return "", "", fmt.Errorf("enterprise hooks: per-user credentials need the target's uid or SID")
	}
	if err := validateEnterpriseHookUserTokenKeyLocation(dataDir); err != nil {
		return "", "", err
	}
	// While a credential rotation has staged the next key, every target is
	// rendered (and verified) with credentials derived from it; the gateway
	// accepts both keys until the rotation commits the staged one.
	key, err := loadEnterpriseHookPendingUserTokenKey(dataDir)
	if err == nil && key == "" {
		if mint {
			key, err = connector.EnsureUserScopedTokenKey(dataDir)
			if err == nil {
				err = alignEnterpriseHookUserTokenKeyOwner(dataDir)
			}
		} else {
			key, err = connector.LoadUserScopedTokenKey(dataDir)
			if err == nil && key == "" {
				err = errors.New("the per-user credential key is missing")
			}
		}
	}
	if err != nil {
		return "", "", fmt.Errorf("enterprise hooks: %w", err)
	}
	hookToken, err := connector.UserScopedHookAPIToken(key, connectorName, identity)
	if err != nil {
		return "", "", fmt.Errorf("enterprise hooks: derive per-user hook credential: %w", err)
	}
	otlpToken := ""
	if scope, ok := connector.OTLPPathTokenScopeForConnector(connectorName); ok {
		otlpToken, err = connector.UserScopedOTLPPathToken(key, scope, identity)
		if err != nil {
			return "", "", fmt.Errorf("enterprise hooks: derive per-user OTLP credential: %w", err)
		}
	}
	return hookToken, otlpToken, nil
}

// enterpriseHookTargetTokens returns the credentials one target's hooks are
// rendered with. The standalone profile binds them to the target's identity
// (the SID here; the Unix guardian passes the uid); every other profile,
// Secure Client included, keeps the connector-scoped credentials.
func enterpriseHookTargetTokens(dataDir, connectorName, identity string, mint bool) (string, string, error) {
	if cfg != nil && cfg.StandaloneEnterprise() {
		if mint {
			return enterpriseHookUserTokenMinter(dataDir, connectorName, identity)
		}
		return enterpriseHookUserTokenLoader(dataDir, connectorName, identity)
	}
	var hookToken, otlpToken string
	var err error
	if mint {
		hookToken, err = enterpriseHookScopedTokenMinter(dataDir, connectorName)
		if err == nil {
			otlpToken, err = enterpriseHookScopedOTLPTokenMinter(dataDir, connectorName)
		}
	} else {
		hookToken, err = loadEnterpriseHookScopedToken(dataDir, connectorName)
		if err == nil {
			otlpToken, err = loadEnterpriseHookScopedOTLPToken(dataDir, connectorName)
		}
	}
	if err != nil {
		return "", "", err
	}
	return hookToken, otlpToken, nil
}

func intPtrValue(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

// enterpriseHookMachinePolicyContractFor applies the deployment-wide
// machine-policy contract to Claude rows only.
func enterpriseHookMachinePolicyContractFor(connectorName, claudeMachineContract string) string {
	if strings.EqualFold(strings.TrimSpace(connectorName), "claudecode") {
		return claudeMachineContract
	}
	return ""
}
