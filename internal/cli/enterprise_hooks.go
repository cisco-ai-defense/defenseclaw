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
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
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
			managed.GatewayServiceAccount(),
		)
	}
	// Permission drift on targets.yaml is re-stamped first when the caller is
	// privileged (the LocalSystem guardian or enumerator, or the installer),
	// and the check runs again. What survives is accepted and logged (an
	// untrusted writer as a boundary finding) on Secure Client only. Structure
	// stays fatal.
	//
	// On standalone a drifted manifest is refused with the strict verdict and
	// never repaired in place (managed.StandaloneRefusesContentDrift): a
	// repair restores the descriptor, not a roster an untrusted writer
	// edited, and the guardian's layout self-heal leaves it unrepaired too.
	// Setup /ensure writes a fresh one (GAP-0561).
	enterpriseHookManifestFileTrustCheck = func(path string) error {
		const label = "hook guardian manifest"
		strictErr := managed.ValidateTrustedFilePath(path, label)
		if strictErr == nil {
			return nil
		}
		if managed.StandaloneRefusesContentDrift() {
			return managed.RefuseStandaloneContentDrift(strictErr)
		}
		if (enterpriseHooksRuntimeGOOS() == "windows" || enterpriseHooksRuntimeGOOS() == "darwin") &&
			enterpriseHookManifestACLRepair(path) == nil &&
			managed.ValidateTrustedFilePath(path, label) == nil {
			return nil
		}
		return managed.ValidateTrustedPolicyFilePath(path, label)
	}
	enterpriseHookManifestACLRepair     = repairEnterpriseHookManifestACL
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
)

// Tests widen the gap between the failed target's retry and a healthy
// target's event repair. Production retains the one-to-fifteen-second cap.
var (
	enterpriseHookWatchRepairRetryMin = time.Second
	enterpriseHookWatchRepairRetryMax = 15 * time.Second
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

// enterpriseHookReconcileConnectorEnabled fails, on a standalone managed
// deployment, the reconcile row of a connector the loaded config does not
// publish (enterprisepolicy.StandaloneConnectorPublished), instead of
// verifying and repairing it. The guardian takes a changed config before the
// hook enumerator rewrites targets.yaml, and its machine policy publish has
// already withdrawn the connector, so a repair of the stale row took the
// per-user route: an administrator's guardrail.connectors.opencode.enabled
// false left a per-user OpenCode plugin that blocked every tool call
// (GAP-2373). The row fails this pass only; the enumerator drops it next.
// Other deployments are unchanged. Tests replace it.
var enterpriseHookReconcileConnectorEnabled = func(name string) error {
	return enterpriseHookReconcileConnectorPublished(cfg, name)
}

func enterpriseHookReconcileConnectorPublished(current *config.Config, name string) error {
	if current == nil || !managed.IsManagedEnterprise(current.DeploymentMode) || !current.StandaloneEnterprise() ||
		strings.TrimSpace(name) == "" || enterprisepolicy.StandaloneConnectorPublished(current, name) {
		return nil
	}
	return fmt.Errorf("enterprise hooks reconcile: connector %q is not enabled by this computer's DefenseClaw configuration, "+
		"so DefenseClaw does not install or repair its hooks for this account; the hook enumerator removes the row on its next pass",
		config.NormalizeConnectorName(name))
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
	Pending bool `json:"pending,omitempty"`
	// Removed records a target whose account or profile was confirmed gone.
	// It remains in the manifest until enumeration catches up, but has no
	// account in which a repair could run.
	Removed bool                           `json:"removed,omitempty"`
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
	Targets         []enterprisehooks.ManifestTarget
	Rows            []enterpriseHookReconcileRow
	Failures        int
	Pending         int
	Repairs         int             `json:"-"`
	RestoredPaths   []string        `json:"-"` // owned files returned to the last verified fingerprint
	RepairedTargets map[string]bool `json:"-"` // target keys whose worker reported a repair
	StateErr        error
	// PolicyErr is a vendor folder that does not protect DefenseClaw's
	// recorded machine policy file (standalone Windows, E3 case c): the
	// publish refused it, so the reconcile is not clean. It is not a
	// target failure and not a state write failure (GAP-0756, GAP-0760).
	PolicyErr           error
	WatchDirs           []string
	WatchExclusiveFiles []string // DC-only writers: react to any event
	WatchSharedFiles    []string // agent + DC writers: react only to Create/Remove/Rename
	// WatchPathOwners ties owned-file events to their manifest targets. A
	// failed target must not change how another target's events are handled.
	WatchPathOwners map[string][]string
}

func (run enterpriseHookReconcileRun) attentionFailures() int {
	failures := 0
	for _, row := range run.Rows {
		if !row.OK && !row.Pending && !row.Removed {
			failures++
		}
	}
	return failures
}

var (
	enterpriseHookReconcileVerifier         = enterpriseHookGuardianVerify
	enterpriseHookReconcileInstaller        = enterprisehooks.Install
	enterpriseHookReconcileSessionAvailable = enterpriseHookTargetSessionAvailable
	// enterpriseHookReconcileTargetRelease names the other DefenseClaw
	// release whose hook-contract lock a target still carries. Tests
	// replace it.
	enterpriseHookReconcileTargetRelease = enterprisehooks.WindowsProtectedTargetFromOtherRelease
	// enterpriseHookReconcileTargetEarlierMatrix reports a target whose
	// agent config still holds an earlier release's hook matrix (GAP-2463).
	// Tests replace it.
	enterpriseHookReconcileTargetEarlierMatrix       = enterprisehooks.WindowsProtectedTargetRunsEarlierHookMatrix
	enterpriseHookReconcileClosedMachineRegistration = enterprisehooks.WindowsProtectedTargetHasClosedMachineRegistration
	// enterpriseHookReconcileMachineRegistration is the closed-registration
	// proof for a deployment whose administrator chose hook fail mode open: the
	// registration without the closed requirement (GAP-0980). Tests replace it.
	enterpriseHookReconcileMachineRegistration = enterprisehooks.WindowsProtectedTargetHasMachineRegistration
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
	enterpriseHookAccountOwnedDataDirLink           = enterpriseHookAccountOwnedDataDirLinkPlatform
	// enterpriseHookForeignDataDirLink reports a link at the account's
	// canonical folder that the account does not own (GAP-0585). Tests
	// replace it.
	enterpriseHookForeignDataDirLink = enterpriseHookForeignDataDirLinkPlatform
)

const enterpriseHookAccountLinkFailure = "enterprise hooks: the account's own DefenseClaw folder link is pending repair"

// enterpriseHookAccountForeignLinkFailure is the guardian error of an account
// whose canonical DefenseClaw folder is a link another principal owns, such as
// an administrator (GAP-0585). The link is never followed, repaired or moved
// aside, so the account has no protection until an administrator removes it.
// Like enterpriseHookAccountLinkFailure it fails only that account's rows:
// status, verify and the administrator lifecycle go on for every other
// account and name this one.
const enterpriseHookAccountForeignLinkFailure = "enterprise hooks: the account's DefenseClaw folder is a link its account does not own; it was left untouched and the account is not protected until an administrator removes the link"

// enterpriseHookStandaloneCanonicalDataDir reports, on a standalone
// deployment only, whether target's effective data directory is the
// canonical <home>\.defenseclaw folder of the account. A manifest target
// that omits data_dir is valid: the Windows runtime resolves it to that same
// folder, so a blank value is the canonical folder, not a missing one.
func enterpriseHookStandaloneCanonicalDataDir(target enterprisehooks.ManifestTarget, home, sid string) bool {
	if cfg == nil || !cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() ||
		strings.TrimSpace(home) == "" || strings.TrimSpace(sid) == "" {
		return false
	}
	dataDir := strings.TrimSpace(target.DataDir)
	return dataDir == "" || sameEnterpriseHookPath(dataDir, filepath.Join(home, ".defenseclaw"))
}

func enterpriseHookTargetAccountLink(target enterprisehooks.ManifestTarget, home, sid string) bool {
	return enterpriseHookStandaloneCanonicalDataDir(target, home, sid) &&
		enterpriseHookAccountOwnedDataDirLink(home, sid)
}

func enterpriseHookTargetForeignLink(target enterprisehooks.ManifestTarget, home, sid string) bool {
	return enterpriseHookStandaloneCanonicalDataDir(target, home, sid) &&
		enterpriseHookForeignDataDirLink(home, sid)
}

// enterpriseHookAccountLinkRow reports a failed standalone row that status,
// verify and the lifecycle excuse because the account's own folder link or a
// link another principal owns keeps that one account unprotected.
func enterpriseHookAccountLinkRow(row enterpriseHookReconcileRow) bool {
	return cfg != nil && cfg.StandaloneEnterprise() && !cfg.SecureClientIntegration() &&
		(enterpriseHookAccountLinkRowStandalone(row) || enterpriseHookAccountForeignLinkRow(row))
}

func enterpriseHookAccountLinkRowStandalone(row enterpriseHookReconcileRow) bool {
	return !row.OK && !row.Pending && row.Result == nil &&
		row.Error == enterpriseHookAccountLinkFailure &&
		strings.TrimSpace(row.UserHome) != "" && strings.TrimSpace(row.SID) != "" &&
		enterpriseHookAccountOwnedDataDirLink(row.UserHome, row.SID)
}

// enterpriseHookAccountForeignLinkRow is enterpriseHookAccountLinkRowStandalone
// for a link the account does not own (GAP-0585). It rechecks the link now, so
// a stale record never excuses an account whose folder was fixed or replaced.
func enterpriseHookAccountForeignLinkRow(row enterpriseHookReconcileRow) bool {
	return !row.OK && !row.Pending && row.Result == nil &&
		row.Error == enterpriseHookAccountForeignLinkFailure &&
		strings.TrimSpace(row.UserHome) != "" && strings.TrimSpace(row.SID) != "" &&
		enterpriseHookForeignDataDirLink(row.UserHome, row.SID)
}

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
	// An earlier release's hook matrix, which lacks only the fail_closed
	// setting this release adds, still runs for it (GAP-2463).
	enterpriseHookAwaitingSignInEarlierMatrix = "its earlier release's hooks still run"
	// The owner or permissions of a signed-out account's own DefenseClaw
	// folder or hooks folder changed (#1105, GAP-0211, GAP-2516); the
	// folder follows after ": ".
	enterpriseHookAwaitingSignInUntrustedFolder = "the owner or permissions of its DefenseClaw folder are not the ones DefenseClaw set"
	// An upgrade left a signed-out or disconnected account with the render
	// of an earlier release's per-user hooks (Copilot, Antigravity, Kiro) and
	// nothing else wrong (GAP-0980): that release's DefenseClaw hook keeps
	// running until the guardian updates it in the account's own Windows
	// session.
	enterpriseHookAwaitingSignInKeepsRunning = "its previous release's DefenseClaw hook keeps running"
	enterpriseHookAwaitingSignInPriorRender  = enterpriseHookAwaitingSignInKeepsRunning + " until this account signs in"
	// The administrator's hook fail mode is open and the machine hook of
	// Claude Code or Codex, which is this release's own, is in place; only the
	// account's registration waits for its sign-in (GAP-0980). The previous
	// release's hook is not what runs for these connectors.
	enterpriseHookAwaitingSignInOpenMode = "its machine hook is in place with hook fail mode open"
)

// enterpriseHookAwaitingSignInKeepsRunningRow reports a guardian row that
// waits for its account's next sign-in while the previous release's hook keeps
// running for it (enterpriseHookAwaitingSignInKeepsRunning).
func enterpriseHookAwaitingSignInKeepsRunningRow(row enterpriseHookReconcileRow) bool {
	return enterpriseHookAwaitingSignInError(row) &&
		strings.HasPrefix(
			strings.TrimPrefix(strings.TrimSpace(row.Error), enterpriseHookAwaitingSignInPrefix+": "),
			enterpriseHookAwaitingSignInKeepsRunning,
		)
}

// enterpriseHookAwaitingSignInMachineHookRow reports a guardian row that waits
// for its account's next sign-in while the machine hook (Claude Code or Codex,
// hook fail mode open) is in place (enterpriseHookAwaitingSignInOpenMode).
func enterpriseHookAwaitingSignInMachineHookRow(row enterpriseHookReconcileRow) bool {
	return enterpriseHookAwaitingSignInError(row) &&
		strings.HasPrefix(
			strings.TrimPrefix(strings.TrimSpace(row.Error), enterpriseHookAwaitingSignInPrefix+": "),
			enterpriseHookAwaitingSignInOpenMode,
		)
}

// enterpriseHookEarlierMatrixRow reports a guardian row that waits for its
// account's next connect while the hooks an earlier release registered still
// guard it (enterpriseHookAwaitingSignInEarlierMatrix). Status reports it as
// enrolled with an older hook matrix, not as pending (GAP-2463).
func enterpriseHookEarlierMatrixRow(row enterpriseHookReconcileRow) bool {
	return enterpriseHookAwaitingSignInError(row) &&
		strings.HasPrefix(
			strings.TrimPrefix(strings.TrimSpace(row.Error), enterpriseHookAwaitingSignInPrefix+": "),
			enterpriseHookAwaitingSignInEarlierMatrix,
		)
}

// enterpriseHookEarlierMatrixState is the guarded-but-not-fail-closed state
// of such a row, for status and verify.
const enterpriseHookEarlierMatrixState = "enrolled with the hook matrix of an earlier DefenseClaw release " +
	"(upgrade pending at the account's next connect): guarded, but a hook spawn error or timeout does not " +
	"block until the guardian upgrades it in the account's own Windows session"

// enterpriseHookAwaitingSignInCause words, for status and verify, why a
// guardian row that waits for its account's next sign-in (its error) is not
// in its configured state yet.
func enterpriseHookAwaitingSignInCause(guardianErr string) string {
	cause := strings.TrimPrefix(strings.TrimSpace(guardianErr), enterpriseHookAwaitingSignInPrefix+": ")
	switch {
	case strings.HasPrefix(cause, enterpriseHookAwaitingSignInOpenMode):
		return "its machine hook is in place, with hook fail mode open as the administrator chose (calls are allowed " +
			"while the gateway is down), and the account's registration finishes when it signs in and the guardian updates it"
	case strings.HasPrefix(cause, enterpriseHookAwaitingSignInPriorRender):
		return "its previous release's DefenseClaw hook keeps running for this account until it signs in and the " +
			"guardian updates it"
	case strings.HasPrefix(cause, enterpriseHookAwaitingSignInFailClosed):
		return "its hooks still fail closed, and the guardian renders hook fail mode open in the account's own " +
			"Windows session at its next sign-in"
	case strings.HasPrefix(cause, enterpriseHookAwaitingSignInEarlierMatrix):
		return enterpriseHookEarlierMatrixState
	case strings.HasPrefix(cause, enterpriseHookAwaitingSignInUntrustedFolder+": "):
		folder := strings.TrimPrefix(cause, enterpriseHookAwaitingSignInUntrustedFolder+": ")
		if end := strings.Index(folder, "; "); end >= 0 {
			folder = folder[:end]
		}
		return "the owner or permissions of its DefenseClaw folder " + folder + " are not the ones DefenseClaw set, " +
			"and the guardian resets them only in the account's own Windows session, at its next sign-in; it is not " +
			"protected until then. Inspect that folder, or remove the account with its profile if it no longer uses DefenseClaw"
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
				// The earlier release's hooks may still run unchanged: then
				// the account is guarded, only not fail-closed, until its
				// next connect (GAP-2463).
				if earlier, matrixErr := enterpriseHookReconcileTargetEarlierMatrix(opts); matrixErr == nil && earlier {
					return enterprisehooks.InstallResult{}, false, fmt.Errorf(
						"%w: %s: DefenseClaw %s registered them without fail_closed, and this release's hooks "+
							"install only in the account's own Windows session; its exact active Windows session is "+
							"unavailable, so the guardian upgrades them at the account's next connect (verification: %v)",
						errEnterpriseHookAwaitingSignIn, enterpriseHookAwaitingSignInEarlierMatrix, written, verifyErr,
					)
				}
				if enterpriseHookReconcileSecureClient() {
					return enterprisehooks.InstallResult{}, false, fmt.Errorf(
						"%w: DefenseClaw %s protected it, and this release's hooks install only in the account's own "+
							"Windows session; its exact active Windows session is unavailable, so the guardian repairs "+
							"it at the account's next sign-in (verification: %v)",
						errEnterpriseHookAwaitingSignIn, written, verifyErr,
					)
				}
				// An older lock alone does not establish that an agent will run a
				// hook. Admit the sign-in wait only when its live machine policy
				// still registers this SID and the hook will fail closed.
				closed, proofErr := enterpriseHookReconcileClosedMachineRegistration(opts)
				if proofErr == nil && closed {
					return enterprisehooks.InstallResult{}, false, fmt.Errorf(
						"%w: DefenseClaw %s protected it, and its exact active Windows session is unavailable, "+
							"so its registered machine hooks fail closed until the account's next sign-in repairs them (verification: %v)",
						errEnterpriseHookAwaitingSignIn, written, verifyErr,
					)
				}
			}
			// A signed-out account whose only failure is the owner or
			// permissions of its own DefenseClaw folder or hooks folder
			// (#1105, GAP-0211) waits for its next sign-in too: only its own
			// Windows session can reset them. As a failure it failed every
			// Setup run and then that run's rollback, which left the gateway
			// and the hook enumerator stopped and disabled for every user
			// (GAP-2516). Status reports it pending and names the folder;
			// any other drift stays a failure.
			if !enterpriseHookReconcileSecureClient() {
				dataDir := strings.TrimSpace(target.DataDir)
				if dataDir == "" {
					dataDir = strings.TrimSpace(opts.DataDir)
				}
				if folder, untrusted := enterpriseHookSignedOutUntrustedFolder(enterpriseHookReconcileRow{
					Error: fmt.Sprintf("enterprise hooks: protected target requires repair but its exact active Windows "+
						"session is unavailable (verification: %v)", verifyErr),
				}, dataDir); untrusted {
					return enterprisehooks.InstallResult{}, false, fmt.Errorf(
						"%w: %s: %s; its exact active Windows session is unavailable, so the guardian repairs it at "+
							"the account's next sign-in (verification: %v)",
						errEnterpriseHookAwaitingSignIn, enterpriseHookAwaitingSignInUntrustedFolder, folder, verifyErr,
					)
				}
			}
			// On Secure Client a committed non-purge uninstall can retire a
			// target; on the standalone profile a roster change can take a
			// target out of its connector's machine runtime selection (a
			// connector removed, or a change undone after the guardian had
			// already revoked it). Either way only the account's own Windows
			// session can select a runtime for it again. With no runtime
			// selected for it (the pending proof) it holds nothing protected
			// and its hooks fail closed (the machine policy keeps the SID
			// registered with no runtime), so it is pending until the account
			// signs in, like an account DefenseClaw never protected. As a
			// failure it made every ensure and repair refuse until that
			// account signed in (GAP-0909). Any target that still has a
			// runtime selected, and every non-deferred target, keeps the
			// failure.
			if enterpriseHookReconcileSecureClient() || (cfg != nil && cfg.StandaloneEnterprise()) {
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
			// An upgrade changed the hooks this account's agents run, and only
			// the account's own Windows session installs them. When the lock
			// names an earlier release the drift is the upgrade's own, and the
			// account must not fail the upgrade (GAP-0980). Two proofs admit
			// the wait, and everything else stays a failure: a second,
			// read-only verify that accepts the earlier release's render
			// (enterprisehooks.InstallOptions.AcceptPriorReleaseRender) passes,
			// so the only difference is that render and the account's
			// previous-release hook keeps running; or the administrator chose
			// hook fail mode open, which the closed-registration proof above
			// cannot hold, and the registration itself is proven. Secure Client
			// has its own branch above.
			if !enterpriseHookReconcileSecureClient() {
				if written, other, releaseErr := enterpriseHookReconcileTargetRelease(opts); releaseErr == nil && other {
					prior := opts
					prior.AcceptPriorReleaseRender = true
					if _, priorErr := enterpriseHookReconcileVerifier(ctx, prior); priorErr == nil {
						return enterprisehooks.InstallResult{}, false, fmt.Errorf(
							"%w: %s: DefenseClaw %s protected it, and this release's hooks install only in the account's own "+
								"Windows session; its exact active Windows session is unavailable, so the guardian updates "+
								"it at the account's next sign-in (verification: %v)",
							errEnterpriseHookAwaitingSignIn, enterpriseHookAwaitingSignInPriorRender, written, verifyErr,
						)
					}
					if strings.EqualFold(strings.TrimSpace(opts.HookFailMode), "open") {
						if registered, proofErr := enterpriseHookReconcileMachineRegistration(opts); proofErr == nil && registered {
							return enterprisehooks.InstallResult{}, false, fmt.Errorf(
								"%w: %s: DefenseClaw %s protected it, and its exact active Windows session is unavailable, "+
									"so the guardian updates it at the account's next sign-in (verification: %v)",
								errEnterpriseHookAwaitingSignIn, enterpriseHookAwaitingSignInOpenMode, written, verifyErr,
							)
						}
					}
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
	attentionFailures := run.attentionFailures()
	if enterpriseHookJSON {
		payload := map[string]any{
			"ok":       attentionFailures == 0 && run.StateErr == nil && run.PolicyErr == nil,
			"manifest": run.Manifest,
			"results":  run.Rows,
		}
		if run.StateErr != nil {
			payload["state_error"] = run.StateErr.Error()
		}
		if run.PolicyErr != nil {
			payload["policy_error"] = run.PolicyErr.Error()
		}
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
		if attentionFailures > 0 || run.StateErr != nil || run.PolicyErr != nil {
			if run.StateErr != nil {
				return fmt.Errorf("enterprise hooks reconcile state write failed: %w", run.StateErr)
			}
			if attentionFailures == 0 {
				return fmt.Errorf("enterprise hooks reconcile refused the machine policy: %w", run.PolicyErr)
			}
			return fmt.Errorf("enterprise hooks reconcile failed for %d target(s)", attentionFailures)
		}
		return nil
	}

	for _, row := range run.Rows {
		label := enterpriseHookReconcileRowLabel(row)
		if row.OK {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s reconciled%s\n", Style("✓", "fg=green", "bold"), label, enterpriseHookAgentVersionNote(row))
		} else if row.Pending {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s pending an exact active Windows session\n", Style("•", "fg=yellow", "bold"), label)
		} else if row.Removed {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %s removed: account or profile no longer exists\n", Style("•", "fg=yellow", "bold"), label)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s %s: %s\n", Style("✗", "fg=red", "bold"), label, row.Error)
		}
	}
	if run.PolicyErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s machine policy: %s\n", Style("✗", "fg=red", "bold"), run.PolicyErr.Error())
	}
	if run.StateErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s hook guardian state: %s\n", Style("✗", "fg=red", "bold"), run.StateErr.Error())
		return fmt.Errorf("enterprise hooks reconcile state write failed: %w", run.StateErr)
	}
	if attentionFailures > 0 {
		return fmt.Errorf("enterprise hooks reconcile failed for %d target(s)", attentionFailures)
	}
	if run.PolicyErr != nil {
		return fmt.Errorf("enterprise hooks reconcile refused the machine policy: %w", run.PolicyErr)
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
	// account, an account-owned folder link, and those waiting for sign-in
	// (enterpriseHookExcusedFailures).
	Warnings []string `json:"warnings,omitempty"`
	// The three failure counts identify those rows, so
	// the Windows lifecycle's manifest adoption accepts exactly them, as
	// verify does.
	RemovedAccountFailures int `json:"removed_account_failures,omitempty"`
	AwaitingSignInFailures int `json:"awaiting_sign_in_failures,omitempty"`
	AccountLinkFailures    int `json:"account_link_failures,omitempty"`
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
		case row.OK, enterpriseHookEarlierMatrixRow(row):
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
		report.RemovedAccountFailures, report.AwaitingSignInFailures, report.AccountLinkFailures = enterpriseHookExcusedFailures(state)
		excusedFailures = report.RemovedAccountFailures + report.AwaitingSignInFailures + report.AccountLinkFailures
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
			case enterpriseHookAccountLinkRow(row):
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
			Style("✓", "fg=green", "bold"), state.SuccessCount, state.PendingCount+report.AwaitingSignInFailures+report.AccountLinkFailures, state.TargetCount)
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
// platform, those waiting for their signed-out account's next sign-in, and
// an account-owned folder link the guardian left untouched. All counts are
// 0 unless every failed row is one of them; status and verify report them as
// warnings instead of failing the whole host.
func enterpriseHookExcusedFailures(state enterpriseHookGuardianState) (removed, awaiting, linked int) {
	for _, row := range state.Results {
		if row.OK || row.Pending {
			continue
		}
		switch {
		case enterpriseHookAccountLinkRow(row):
			linked++
		case enterpriseHookRemovedAccountRow(row):
			removed++
		case enterpriseHookAwaitingSignInRow(row):
			awaiting++
		default:
			return 0, 0, 0
		}
	}
	if removed+awaiting+linked != state.FailureCount {
		return 0, 0, 0
	}
	return removed, awaiting, linked
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
		if enterpriseHookEarlierMatrixRow(row) {
			return fmt.Sprintf("%s for %s is %s",
				strings.TrimSpace(row.Connector), account, enterpriseHookEarlierMatrixState)
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
	var trust func(string) error
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		trust = func(path string) error {
			if err := enterpriseHookGuardianStateFileTrustCheck(path); err != nil {
				return fmt.Errorf("validate hook guardian state %s: %w", path, err)
			}
			return nil
		}
	}
	data, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian state", enterpriseHookGuardianStateMaxBytes, trust)
	if err != nil || !exists {
		return enterpriseHookGuardianState{}, exists, err
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
	// (enterpriseHookHermesSignedOutRow), own-folder rows
	// (enterpriseHookSignedOutUntrustedFolderVerifyRow) and the rows failed only by an
	// enterpriseHookUserFileFault that the guardian last recorded as
	// protected; the protected records are compared with them as protected.
	RecordedProtected map[string]bool
	AuthorizationErr  error
}

// enterpriseHookUserFileFault is a verify row error whose only cause is a
// file in the target account's own profile that DefenseClaw reads but the
// guardian's pass and Setup readiness report as a warning (on Windows, the
// Claude Code user settings the migration cannot finish): the row fails, but
// the guardian's protected records, which recorded the row protected, are no
// second fault (GAP-0031).
type enterpriseHookUserFileFault struct{ err error }

func (f enterpriseHookUserFileFault) Error() string { return f.err.Error() }
func (f enterpriseHookUserFileFault) Unwrap() error { return f.err }

// enterpriseHookVerifyExcusedNote describes why an excused row remains
// pending. A live account's folder link must not receive the removed-account
// guidance.
func enterpriseHookVerifyExcusedNote(run enterpriseHookVerifyRun, row enterpriseHookReconcileRow) string {
	key := enterpriseHookProtectedTargetKey(row)
	if guardianErr, ok := run.AwaitingSignIn[key]; ok && key != "" {
		return " (pending until the account signs in: " + enterpriseHookAwaitingSignInCause(guardianErr) + ")"
	}
	if row.Error == enterpriseHookAccountLinkFailure {
		return " (the account remains pending until its DefenseClaw folder link is repaired)"
	}
	if row.Error == enterpriseHookAccountForeignLinkFailure {
		return " (the account stays unprotected until an administrator removes the link at its DefenseClaw folder)"
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

// enterpriseHookManagedEnrollmentVerifier compares the protected enrollment set
// the Guardian published with the one verify expects.
var enterpriseHookManagedEnrollmentVerifier = verifyEnterpriseHookManagedEnrollments

func runEnterpriseHookVerifyAttemptWithScope(ctx context.Context, registrationOnly bool) (enterpriseHookVerifyRun, error) {
	if cfg == nil {
		return enterpriseHookVerifyRun{Manifest: enterpriseHookManifest}, fmt.Errorf("enterprise hooks verify: config is not loaded")
	}
	if enterpriseHooksStandaloneUnixActive() {
		return runEnterpriseHookVerifyAttemptStandaloneUnix(ctx, registrationOnly)
	}
	run := enterpriseHookVerifyRun{Manifest: enterpriseHookManifest}
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if err := enterpriseHookManifestFileTrustCheck(enterpriseHookManifest); err != nil {
			return run, fmt.Errorf("enterprise hooks verify: manifest trust check failed: %w", err)
		}
		if err := validateEnterpriseHookManagedRuntime(); err != nil {
			return run, err
		}
	}
	return runEnterpriseHookVerifyAttemptRows(ctx, registrationOnly)
}

// runEnterpriseHookVerifyAttemptRows verifies every manifest row of a
// deployment whose manifest and runtime were already found trusted, then the
// exact protected enrollment set. cfg is loaded.
func runEnterpriseHookVerifyAttemptRows(ctx context.Context, registrationOnly bool) (enterpriseHookVerifyRun, error) {
	run := enterpriseHookVerifyRun{Manifest: enterpriseHookManifest}
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
		removed, awaiting, linked := enterpriseHookExcusedFailures(guardianState)
		excused = removed + awaiting + linked
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
	// The targets the Guardian leaves out of the protected enrollment set it
	// publishes (a failed target that was never protected, a removed account).
	// Verify compares the published set with the enabled manifest minus
	// exactly these, after the rows below say which they are.
	unenrolled := map[string]struct{}{}
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
		if enterpriseHookGuardianTargetRemoved(ctx, target, row, targetErr) {
			row.Removed = true
			row.Error = "enterprise hooks: target account or profile removed"
			run.Failures++
			if prior, ok := recorded[enterpriseHookProtectedTargetKey(row)]; ok && enterpriseHookRemovedAccountRow(prior) {
				run.Excused = append(run.Excused, row)
				unenrolled[enterpriseHookEnrollmentUnit(target)] = struct{}{}
			}
			run.Rows = append(run.Rows, row)
			continue
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
		if targetErr == nil && enterpriseHookTargetForeignLink(target, resolved.home, resolved.sid) {
			targetErr = errors.New(enterpriseHookAccountForeignLinkFailure)
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
		if targetErr == nil && previousProtection.PreviouslyProtected &&
			recorded[enterpriseHookProtectedTargetKey(row)].Error == enterpriseHookAccountLinkFailure &&
			enterpriseHookTargetAccountLink(target, resolved.home, resolved.sid) {
			targetErr = errors.New(enterpriseHookAccountLinkFailure)
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
		if waiting, ok := enterpriseHookSignedOutUntrustedFolderVerifyRow(target, row, targetErr, recorded); ok {
			// Changed after the guardian last proved it, while its account
			// is signed out: pending until that account signs in, compared
			// with the protected records as the guardian last recorded it.
			row.OK, row.Pending, row.Result, row.Error = false, false, nil, targetErr.Error()
			run.Failures++
			run.Excused = append(run.Excused, row)
			if run.AwaitingSignIn == nil {
				run.AwaitingSignIn = map[string]string{}
			}
			run.AwaitingSignIn[enterpriseHookProtectedTargetKey(row)] = waiting
			if run.RecordedProtected == nil {
				run.RecordedProtected = map[string]bool{}
			}
			run.RecordedProtected[enterpriseHookProtectedTargetKey(row)] = true
			run.Rows = append(run.Rows, row)
			continue
		}
		if targetErr != nil {
			row.OK = false
			row.Error = targetErr.Error()
			run.Failures++
			var userFile enterpriseHookUserFileFault
			if errors.As(targetErr, &userFile) && recorded[enterpriseHookProtectedTargetKey(row)].OK {
				// The row fails on a file in the account's own profile
				// only, and the guardian, whose readiness reports that
				// file as a warning, recorded it protected: the records
				// still describe it, so they are not a second fault.
				if run.RecordedProtected == nil {
					run.RecordedProtected = map[string]bool{}
				}
				run.RecordedProtected[enterpriseHookProtectedTargetKey(row)] = true
			}
			excusedBefore := len(run.Excused)
			if excused > 0 && row.Error == enterpriseHookAccountLinkFailure &&
				enterpriseHookAccountLinkRow(recorded[enterpriseHookProtectedTargetKey(row)]) &&
				enterpriseHookTargetAccountLink(target, row.UserHome, row.SID) {
				run.Excused = append(run.Excused, row)
			} else if excused > 0 && row.Error == enterpriseHookAccountForeignLinkFailure &&
				enterpriseHookAccountForeignLinkRow(recorded[enterpriseHookProtectedTargetKey(row)]) &&
				enterpriseHookTargetForeignLink(target, row.UserHome, row.SID) {
				run.Excused = append(run.Excused, row)
			} else if excused > 0 && enterpriseHookRemovedAccountRow(row) {
				run.Excused = append(run.Excused, row)
			} else if excused > 0 && enterpriseHookVerifyAwaitingSignIn(awaitingSignIn, target, row) {
				run.Excused = append(run.Excused, row)
				if run.AwaitingSignIn == nil {
					run.AwaitingSignIn = map[string]string{}
				}
				run.AwaitingSignIn[enterpriseHookProtectedTargetKey(row)] = awaitingSignIn[enterpriseHookProtectedTargetKey(row)]
			}
			if len(run.Excused) > excusedBefore {
				enterpriseHookNoteExcusedUnenrolled(unenrolled, target, previousProtection.PreviouslyProtected)
			}
		}
		run.Rows = append(run.Rows, row)
	}
	if err := enterpriseHookManagedEnrollmentVerifier(enterpriseHookEnrollmentManifest(manifest, unenrolled), apiAddr); err != nil {
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
	previousState, _, _ := loadEnterpriseHookGuardianState(cfg.DataDir)
	reportEnterpriseHookManifestSkippedRowsPlatform(enterpriseHookManifest, manifest.Skipped)
	run.ManifestSHA256 = manifestSHA256
	apiAddr := strings.TrimSpace(enterpriseHookAPIAddr)
	if apiAddr == "" {
		apiAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Gateway.APIPort)
	}
	proxyAddr := strings.TrimSpace(enterpriseHookProxyAddr)
	if proxyAddr == "" {
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Guardrail.Port)
	}
	// An off-roster marker of a connector the config publishes again goes
	// before the machine policy is published again, so it never survives into
	// the pass that republishes the policy (the Windows standalone guardian
	// only; the hook allows only while the policy is absent).
	enterpriseHookStandalonePlatformClearStaleOffRoster(os.Stderr)
	// Revoke removed/disabled SIDs before touching any target runtime. This
	// makes stale enrollment fail closed even when a later repair fails.
	// A link at a connector's vendor folder fails that connector's targets
	// below, by name, and does not stop the pass: the other connectors are
	// revoked and applied, and the manifest is activated (GAP-0879).
	var linkRows map[string]string
	if err := enterpriseHookReconcileSyncEnrollments(manifest, apiAddr, false); err != nil {
		linkFailures := enterpriseHookLinkFailures(err)
		if linkFailures == nil {
			return run, fmt.Errorf(
				"enterprise hooks reconcile: revoke stale protected enrollments: %w",
				err,
			)
		}
		linkRows = linkFailures.rowErrors()
		// The row names the link; the cause (access denied, a trust failure) is
		// logged once, so a real failure next to a link stays visible.
		for _, failure := range linkFailures.Failures {
			enterpriseHookLinkCauseFolds.emit(os.Stderr, time.Now(), "link:"+failure.Connector, failure.Cause.Error(),
				"the same link cause", failure.causeLine())
		}
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
	run.PolicyErr = enterpriseHookStandalonePlatformPrepare(os.Stderr)
	openCodePorts, openCodePortsErr := enterpriseHookStandaloneOpenCodePorts(ctx, manifest)
	if openCodePortsErr != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise hooks: %v\n", openCodePortsErr)
	}

	rows := make([]enterpriseHookReconcileRow, 0, len(manifest.Targets))
	failures := 0
	pending := 0
	repairs := 0
	var restored []enterpriseHookGuardianRestore
	var notices []enterpriseHookGuardianNotice
	pendingTargets := make([]enterprisehooks.ManifestTarget, 0)
	unenrolled := map[string]struct{}{}
	watchDirs := map[string]struct{}{}
	exclusiveFiles := map[string]struct{}{}
	sharedFiles := map[string]struct{}{}
	var watchPathOwners map[string][]string
	if cfg.StandaloneEnterprise() {
		watchPathOwners = map[string][]string{}
	}
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
		var watchPathErr error
		row := enterpriseHookReconcileRow{
			User:      strings.TrimSpace(target.User),
			UserHome:  strings.TrimSpace(target.UserHome),
			SID:       strings.TrimSpace(target.SID),
			Connector: strings.TrimSpace(target.Connector),
		}
		token := ""
		otlpToken := ""
		var previousProtection enterpriseHookPreviousProtection
		// ledgerUnreadable records that the protection ledger could not be
		// read for this target, so "not protected" is unknown rather than
		// confirmed and the target must keep its enrollment.
		ledgerUnreadable := false
		resolved, err := resolveEnterpriseHookTargetValues(target.User, target.UserHome, intPtrValue(target.UID), intPtrValue(target.GID), target.SID, target.DataDir)
		resolveFailed := err != nil
		if err == nil {
			row.SID = strings.TrimSpace(resolved.sid)
			row.UserHome = strings.TrimSpace(resolved.home)
		}
		if enterpriseHookGuardianTargetRemoved(ctx, target, row, err) {
			row.Removed = true
			row.RevokeProtection = true
			row.Error = "enterprise hooks: target account or profile removed"
			rows = append(rows, row)
			failures++
			unenrolled[enterpriseHookEnrollmentUnit(target)] = struct{}{}
			enterpriseHookTargetHealth.clear(row)
			continue
		}
		if err == nil {
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
				ledgerUnreadable = true
			}
		}
		if err == nil {
			// A row of a connector the loaded config no longer enables is
			// stale: the enumerator has not dropped it yet (GAP-2373).
			err = enterpriseHookReconcileConnectorEnabled(target.Connector)
			if err != nil {
				// The config no longer publishes the connector, so no row of
				// it keeps a protected claim: carried forward from the last
				// pass, it would keep a leftover credential accepted by the
				// gateway until the enumerator drops the row (GAP-0916).
				row.RevokeProtection = true
			}
		}
		if err == nil && enterpriseHookTargetForeignLink(target, resolved.home, resolved.sid) {
			// A link another principal owns at the account's folder is never
			// followed, repaired or moved aside. Fail only this account's
			// rows, by name, so the other accounts keep their protection and
			// the administrator lifecycle goes on (GAP-0585).
			err = errors.New(enterpriseHookAccountForeignLinkFailure)
		}
		if err == nil {
			if linkRow, linked := linkRows[strings.ToLower(strings.TrimSpace(target.Connector))]; linked {
				// The vendor folder of this connector is a link: nothing is
				// written through it, and this connector's rows fail by name.
				err = errors.New(linkRow)
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
		if err == nil && previousProtection.PreviouslyProtected &&
			enterpriseHookTargetAccountLink(target, resolved.home, resolved.sid) {
			// The link itself belongs to this account. Leave its contents
			// untouched and record the account as unprotected; the other
			// targets can still establish their own protected coverage.
			err = errors.New(enterpriseHookAccountLinkFailure)
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
				WindowsDeferredFirstEnrollment:     enterpriseHookDeferredFirstEnrollment(target, previousProtection),
				// Standalone Amp and OpenCode only; empty on Secure Client.
				ForeignHookGuardBinary:      standaloneForeignHookGuardBinary(target.Connector),
				ManagedHookBinary:           standaloneManagedHookBinary(),
				MachinePolicyContractID:     enterpriseHookMachinePolicyContractFor(target.Connector, claudeMachineContract),
				OpenCodeServicePort:         openCodePorts[strings.ToUpper(resolved.sid)],
				OpenCodeServicePortRequired: runtime.GOOS == "windows" && cfg.StandaloneEnterprise() && strings.EqualFold(target.Connector, "opencode"),
			}
			// Repair the user's objects as root before anything validates them.
			err = repairEnterpriseHookUserTargetPlatform(target, opts)
			if err == nil {
				if dirs, watchErr := enterprisehooks.WatchDirs(opts); watchErr == nil {
					for _, dir := range dirs {
						watchDirs[dir] = struct{}{}
					}
				} else if runtime.GOOS == "windows" && cfg.StandaloneEnterprise() {
					watchPathErr = fmt.Errorf("list watch directories: %w", watchErr)
				}
			}
			if own, filesErr := enterprisehooks.WatchOwnedFiles(opts); filesErr == nil {
				owner := enterpriseHookProtectedTargetKey(row)
				for _, f := range own.ExclusiveWriter {
					exclusiveFiles[f] = struct{}{}
					if watchPathOwners != nil {
						enterpriseHookWatchAddPathOwner(watchPathOwners, f, owner)
					}
				}
				for _, f := range own.SharedWriter {
					sharedFiles[f] = struct{}{}
					if watchPathOwners != nil {
						enterpriseHookWatchAddPathOwner(watchPathOwners, f, owner)
					}
				}
			} else if runtime.GOOS == "windows" && cfg.StandaloneEnterprise() {
				watchPathErr = errors.Join(watchPathErr, fmt.Errorf("list owned watch files: %w", filesErr))
			}
			platformDirs, platformFiles := enterpriseHookPlatformWatchFiles(target.Connector, resolved.home)
			for _, dir := range platformDirs {
				watchDirs[dir] = struct{}{}
			}
			enterpriseHookWatchAddExclusiveOwnedFiles(exclusiveFiles, watchPathOwners, platformFiles, enterpriseHookProtectedTargetKey(row))
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
						reportEnterpriseHookTargetRepairedPlatform(target, result)
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
			enterpriseHookTargetHealth.clear(row)
			rows = append(rows, row)
			continue
		}
		if watchPathErr != nil {
			err = errors.Join(err, fmt.Errorf("watch target paths: %w", watchPathErr))
			recheck = false
		}
		if err != nil {
			protected := previousProtection.PreviouslyProtected
			if resolveFailed {
				// The profile no longer resolves (an FSLogix or roaming
				// profile detached, a renamed folder). Look the target up by
				// its manifest identity so a protected user keeps protection.
				var ledgerErr error
				row.SID = enterpriseHookUnresolvedTargetIdentity(cfg.DataDir, target)
				protected, ledgerErr = previousEnterpriseHookSuccess(
					cfg.DataDir,
					target.User,
					target.UserHome,
					row.SID,
					target.Connector,
				)
				if ledgerErr != nil {
					ledgerUnreadable = true
				}
			}
			failures++
			row.OK = false
			row.Error = err.Error()
			if !protected && enterpriseHookTargetUnavailable(err) {
				// A never-protected user who is signed out or whose profile
				// is detached has nothing to protect yet. It is recorded as a
				// failed row rather than a new pending kind so that state
				// files stay readable by earlier releases after a rollback;
				// the reason says it is waiting, and it is retried every
				// tick without blocking anyone else.
				row.Error = "pending: " + enterpriseHookBoundReason(err.Error())
			}
			if enterpriseHookFailedTargetUnenrolls(protected, ledgerUnreadable) {
				unenrolled[enterpriseHookEnrollmentUnit(target)] = struct{}{}
			}
			enterpriseHookTargetHealth.observe(row, row.Error)
		} else {
			enterpriseHookTargetHealth.clear(row)
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
			row.Error = err.Error()
		})
	enterpriseHookStartup.target(os.Stderr, len(manifest.Targets), len(manifest.Targets))
	if cfg.StandaloneEnterprise() {
		if err := ctx.Err(); err != nil {
			return run, err
		}
	}
	// A restore that is not recorded is not named by status, so the pass
	// reports it and retries instead of waiting for the interval (GAP-0626).
	restoreErr := recordEnterpriseHookGuardianRestores(os.Stderr, cfg.DataDir, rows, restored)
	if runtime.GOOS == "windows" && enterpriseHookGuardianRestoresEnabled() {
		// The standalone Windows guardian; Linux and macOS record theirs
		// in their own reconcile, and Secure Client records none.
		writeEnterpriseHookGuardianNotices(os.Stderr, cfg.DataDir, notices)
	}

	// One failed target never blocks the others. Deferred staging and the
	// exact enrollment publication run for every target that succeeded, is
	// pending, or failed but still holds its last protected state; that
	// includes a target an earlier release protected that waits for its
	// signed-out account (GAP-0644), which keeps the SID enrollment that
	// release published. A failed target that was never protected, and a
	// non-deferred pending target, are left out of the published set until a
	// later tick succeeds for them.
	enrollmentManifest := enterpriseHookEnrollmentManifest(manifest, unenrolled)
	enrollmentErr := enterpriseHookReconcileStageDeferredPolicies(
		enrollmentManifest,
		pendingTargets,
		apiAddr,
	)
	if enrollmentErr == nil {
		enrollmentErr = enterpriseHookReconcileSyncEnrollments(enrollmentManifest, apiAddr, true)
		if linkFailures := enterpriseHookLinkFailures(enrollmentErr); linkFailures != nil && linkFailures.coveredBy(linkRows) {
			// The pre-pass failed the rows of every connector named here, so the
			// failed rows carry the failure. A link that appeared after the
			// pre-pass has no failed row: the pass stays failed.
			enrollmentErr = nil
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
	if stateErr == nil {
		logEnterpriseHookRemovedTransitions(os.Stderr, previousState.Results, rows)
	}
	if stateErr == nil && enrollmentErr != nil {
		stateErr = fmt.Errorf(
			"publish exact protected enrollment set: %w",
			enrollmentErr,
		)
	}
	if stateErr == nil && restoreErr != nil {
		stateErr = fmt.Errorf("record the restored targets: %w", restoreErr)
	}
	stateErr = errors.Join(stateErr, openCodePortsErr)
	enterpriseHookStandalonePlatformFinish(ctx, os.Stderr, rows, time.Now())
	run.Rows = rows
	run.Failures = failures
	run.Pending = pending
	run.Repairs = repairs
	run.StateErr = stateErr
	run.WatchDirs = sortedEnterpriseHookWatchDirs(watchDirs)
	run.WatchExclusiveFiles = sortedEnterpriseHookWatchDirs(exclusiveFiles)
	run.WatchSharedFiles = sortedEnterpriseHookWatchDirs(sharedFiles)
	run.WatchPathOwners = watchPathOwners
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

// Replaceable only by watch-loop tests that control when a target changes.
var enterpriseHookWatchReconcileOnce = runEnterpriseHookReconcileOnce

// Replaceable by watch-loop tests so platform background checks do not
// outlive a test's temporary guardian configuration.
var enterpriseHookWatchPlatformWatch = enterpriseHookStandalonePlatformWatch

// Tests can select the standalone scheduling path without privileged setup.
var enterpriseHookWatchTargetScoped = func() bool { return cfg != nil && cfg.StandaloneEnterprise() }

// Replaceable by watch-loop tests that advance the interval only after the
// preceding pass is ready, without depending on a short wall-clock tick.
var enterpriseHookWatchIntervalTicker = func(interval time.Duration) (<-chan time.Time, func()) {
	ticker := time.NewTicker(interval)
	return ticker.C, ticker.Stop
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
	// The standalone guardian uses target-scoped retry and event state.
	// Secure Client and OSS watch commands retain their existing behavior.
	legacyWatch := !enterpriseHookWatchTargetScoped()
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
	var windowsOwnedPaths map[string]string
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
	// Cleared when the filesystem pass runs or another pass restores that
	// path; an unrelated interval leaves it for the pending debounce.
	var lastTriggerPath string
	var lastTriggerOp fsnotify.Op
	var repairRetries enterpriseHookWatchRetries
	var failedOwnedPaths map[string]bool
	var previousRun enterpriseHookReconcileRun
	legacyRepairRetryNeeded := false
	legacyRepairRetryDelay := time.Duration(0)
	// A failure that lasts (a link at a vendor folder waits for an administrator)
	// is logged on its first pass and counted on the retries that follow.
	// Only the standalone Windows guardian folds; every other guardian logs each line.
	logReconcileFailure := func(reason string, err error) {
		line := fmt.Sprintf("[hook-guardian] reconcile after %s failed: %s\n", reason, err)
		if reason == "interval" {
			line = fmt.Sprintf("[hook-guardian] interval reconcile failed: %s\n", err)
		}
		if !enterpriseHookFoldRepeats() {
			fmt.Fprint(cmd.ErrOrStderr(), line)
			return
		}
		enterpriseHookRepeatFolds.emit(cmd.ErrOrStderr(), time.Now(), "reconcile", err.Error(), "the same reconcile failure", line)
	}
	logRepairRetry := func(delay time.Duration) {
		line := fmt.Sprintf("[hook-guardian] repair incomplete; retrying in %s\n", delay)
		if !enterpriseHookFoldRepeats() {
			fmt.Fprint(cmd.ErrOrStderr(), line)
			return
		}
		enterpriseHookRepeatFolds.emit(cmd.ErrOrStderr(), time.Now(), "retry", "retry", "the repair retry", line)
	}
	repairRetryNeeded := func() bool {
		if legacyWatch {
			return legacyRepairRetryNeeded
		}
		_, needed := repairRetries.nextDue()
		return needed
	}
	// degraded is set when the startup reconcile failed in managed mode. The
	// service keeps running and retrying instead of exiting into an SCM
	// restart loop; the first successful reconcile clears it.
	degraded := false
	reconcile := func(reason string, overrideCtx ...context.Context) (bool, error) {
		enterpriseHookStandaloneConfigRefresh(cmd.ErrOrStderr())
		enterpriseHookBeforeWatchReconcile(cmd.ErrOrStderr())
		// Repair the gateway's data objects at start and on every pass. The
		// results are logged by the helper and never fail the pass.
		repairEnterpriseHookGatewayDataPathsPlatform()
		// Then the install tree, StateRoot records, policy folders and
		// service descriptors, so later drift heals without Setup Repair.
		repairEnterpriseHookManagedInstallPlatform()
		reconcileCtx := cmd.Context()
		if len(overrideCtx) != 0 {
			reconcileCtx = overrideCtx[0]
		}
		// A retry or interval can restore an owned file before its queued
		// filesystem event gets a pass. Retain the file state at the start of
		// every standalone Unix pass so that restoration belongs to this pass.
		var beforeOwned, lastVerifiedOwned map[string]string
		if !legacyWatch && runtime.GOOS != "windows" {
			beforeOwned = make(map[string]string, len(exclusiveOwned))
			lastVerifiedOwned = maps.Clone(ownedSnapshot)
			takeEnterpriseHookOwnedSnapshot(beforeOwned, exclusiveOwned, nil, enterpriseHookOwnedFileFingerprint)
		}
		if !legacyWatch && reason == "fsnotify" && previousRun.ManifestSHA256 != "" {
			reconcileCtx = context.WithValue(reconcileCtx, enterpriseHookWatchPriorRunKey{}, previousRun)
		}
		run, err := enterpriseHookWatchReconcileOnce(reconcileCtx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				if run.Repairs > 0 {
					// The pass was interrupted after its workers put targets
					// back: the next pass finds them in order, so this line is
					// the only reconcile log of those repairs (GAP-0754).
					writeEnterpriseHookReconcileLog(cmd.ErrOrStderr(), reason, "interrupted", run, len(watched), true, "")
				}
				return false, err
			}
			if legacyWatch {
				legacyRepairRetryNeeded = true
			} else {
				repairRetries.observe(reason, run, err, time.Now())
			}
			return false, err
		}
		if degraded {
			degraded = false
			fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] recovered from degraded startup after %s reconcile\n", reason)
			writeGuardianStateOrLog(cmd.ErrOrStderr(), guardianstate.StateReady)
		}
		enterpriseHookAfterWatchReconcile(cmd.Context(), cmd.ErrOrStderr(), run)
		dirs := append([]string{filepath.Dir(filepath.Clean(enterpriseHookManifest))}, run.WatchDirs...)
		if err := syncEnterpriseHookWatchDirs(fsw, watched, dirs); err != nil &&
			!enterpriseHookWatchFailureToleratedPlatform(err) {
			// Match the runEnterpriseHookReconcileOnce error path: mark
			// retry so the caller schedules a backoff attempt rather than
			// waiting for the periodic interval to recover.
			if legacyWatch {
				legacyRepairRetryNeeded = true
			} else {
				repairRetries.observe(reason, run, err, time.Now())
			}
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
		windowsOwnedPaths = nil
		if runtime.GOOS == "windows" && !legacyWatch {
			windowsOwnedPaths = enterpriseHookWatchCaseFoldedOwnedPaths(exclusiveOwned, sharedOwned)
		}
		for k := range foundSnapshot {
			delete(foundSnapshot, k)
		}
		for k, v := range ownedSnapshot {
			foundSnapshot[k] = v
		}
		takeEnterpriseHookOwnedSnapshot(ownedSnapshot, exclusiveOwned, sharedOwned, enterpriseHookOwnedFileFingerprint)
		if beforeOwned != nil {
			var observedDrift map[string]bool
			if observed, ok := reconcileCtx.Value(enterpriseHookWatchPassWritesKey{}).(*enterpriseHookWatchPassWrites); ok {
				observedDrift = observed.snapshot()
			}
			run.RestoredPaths = enterpriseHookWatchRestoredOwnedFiles(previousRun, lastVerifiedOwned, beforeOwned, ownedSnapshot,
				observedDrift, run.RepairedTargets, run.WatchExclusiveFiles)
			if len(run.RestoredPaths) > run.Repairs {
				run.Repairs = len(run.RestoredPaths)
			}
		}
		previousRun = run
		if !legacyWatch {
			failedOwnedPaths = enterpriseHookWatchFailedOwnedPaths(run)
		}
		status := "ok"
		if run.attentionFailures() > 0 || run.StateErr != nil || run.PolicyErr != nil {
			status = "attention"
		}
		rowsHash := enterpriseHookReconcileRowsHash(run.Rows)
		changed := enterpriseHookReconcileChanged(rowsHash, lastRowsHash, run.Repairs)
		lastRowsHash = rowsHash
		triggerTag := ""
		if lastTriggerPath != "" && (reason == "fsnotify" || slices.Contains(run.RestoredPaths, lastTriggerPath)) {
			// Attribute the reconcile to the specific fsnotify event
			// that armed the debounce, including a retry or interval that
			// completed the pending file work before its own debounce fired.
			triggerTag = fmt.Sprintf(" trigger_path=%q trigger_op=%s", lastTriggerPath, lastTriggerOp)
			lastTriggerPath = ""
			lastTriggerOp = 0
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
		if run.StateErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] state write failed: %s\n", run.StateErr)
		}
		if legacyWatch {
			legacyRepairRetryNeeded = run.Failures > 0 || run.StateErr != nil || run.PolicyErr != nil
			if !legacyRepairRetryNeeded {
				legacyRepairRetryDelay = 0
			}
		} else {
			repairRetries.observe(reason, run, nil, time.Now())
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
	managedMode := cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode)
	if managedMode {
		dataDir := cfg.DataDir
		enterprisehooks.WindowsManagedRuntimeRetirePreviousGenerationAllowed = func() bool {
			return enterpriseHookNoLifecycleTransactionPending(dataDir)
		}
	}
	// The standalone Windows guardian records how far this first reconcile
	// has come, for the Setup coverage wait (GAP-0401).
	enterpriseHookStartup.begin(cmd.ErrOrStderr(), cfg.DataDir)
	_, startupErr := reconcile("startup")
	enterpriseHookStartup.end(cmd.ErrOrStderr())
	if startupErr != nil {
		if !managedMode {
			return startupErr
		}
		if isMissingManifestErr(startupErr) {
			if waitErr := waitForEnterpriseHookManifestManaged(cmd.Context(), cmd.ErrOrStderr(), fsw, events); waitErr != nil {
				if contextErr := cmd.Context().Err(); contextErr != nil {
					return contextErr
				}
				startupErr = waitErr
			} else {
				// Manifest is present now — re-run the startup reconcile so
				// the watch loop enters its main select with a valid row
				// set, hashes, and watched dirs.
				_, startupErr = reconcile("startup_after_wait")
			}
		}
		if startupErr != nil {
			// A managed guardian never exits on a startup reconcile error.
			// It starts degraded, keeps the manifest folder watched, and
			// retries on the repair backoff until a reconcile succeeds.
			degraded = true
			if legacyWatch {
				legacyRepairRetryNeeded = true
			} else {
				repairRetries.observe("startup", enterpriseHookReconcileRun{}, startupErr, time.Now())
			}
			managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
				"component": "hook-guardian",
				"path":      filepath.Clean(enterpriseHookManifest),
				"reason":    "startup reconcile failed: " + startupErr.Error(),
			})
			manifestPath := filepath.Clean(enterpriseHookManifest)
			if err := syncEnterpriseHookWatchDirs(fsw, watched, []string{filepath.Dir(manifestPath)}); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] degraded: could not watch manifest folder: %s\n", err)
			}
			exclusiveOwned[manifestPath] = struct{}{}
		}
	}
	if !degraded {
		// Successful startup reconcile ⇒ manifest is loaded ⇒ publish
		// the guardian-side "ready" state so the sidecar's health surface
		// can collapse to overall `ready`.
		writeGuardianStateOrLog(cmd.ErrOrStderr(), guardianstate.StateReady)
	}
	hostChecks := newEnterpriseHookHostChecks(cfg)
	hostChecks.Run()

	intervalTicks, stopIntervalTicker := enterpriseHookWatchIntervalTicker(enterpriseHookWatchInterval)
	defer stopIntervalTicker()
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
	debounceHasHealthyPath := false
	debounceKeepFailedPaths := false
	// Failed owned events yield to healthy events in the same burst, then
	// run in a follow-up pass while their own retry deadline remains intact.
	var deferredFailedPaths []string
	deferredFailedAll := false
	// debounceArmedAt is when the pending debounce was first armed.
	var debounceArmedAt time.Time
	repairRetry := time.NewTimer(time.Hour)
	if !repairRetry.Stop() {
		<-repairRetry.C
	}
	defer repairRetry.Stop()
	repairRetryPending := false
	var repairRetryDue time.Time
	// Keep failed-repair backoff independent from filesystem debounce. A
	// target that can generate owned-file events must not be able to postpone
	// the retry that replaces a released locked or oversized artifact.
	scheduleRepairRetry := func() {
		if legacyWatch {
			if !legacyRepairRetryNeeded || repairRetryPending {
				return
			}
			legacyRepairRetryDelay = enterpriseHookWatchNextRepairRetryDelay(legacyRepairRetryDelay)
			resetEnterpriseHookWatchTimer(repairRetry, legacyRepairRetryDelay)
			repairRetryPending = true
			logRepairRetry(legacyRepairRetryDelay)
			return
		}
		due, needed := repairRetries.nextDue()
		if !needed || (repairRetryPending && due.Equal(repairRetryDue)) {
			return
		}
		delay := time.Until(due)
		if delay < 0 {
			delay = 0
		}
		resetEnterpriseHookWatchTimer(repairRetry, delay)
		repairRetryPending = true
		repairRetryDue = due
		logRepairRetry(delay.Round(time.Millisecond))
	}
	cancelRepairRetry := func() {
		// A pass that needs no retry is a pass that succeeded: print the counted
		// repeats and let the next failure show again.
		enterpriseHookRepeatFolds.reset(cmd.ErrOrStderr())
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
		repairRetryDue = time.Time{}
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
		debounceHasHealthyPath = false
		debounceKeepFailedPaths = false
		deferredFailedPaths, deferredFailedAll = nil, false
	}
	scheduleRepairRetry()
	// Windows standalone: restore the managed OpenCode plugin as soon as its
	// attributes change, without waiting for the interval pass.
	enterpriseHookWatchPlatformWatch(cmd.Context(), cmd.ErrOrStderr())
	// A local account created or changed (useradd, usermod) gets its
	// identity record within seconds, before its first hook (GAP-2108).
	accountChanges := enterpriseHookAccountDatabaseChanges(cmd.Context())
	// A pass may spend its worker timeout on an unavailable account. Keep
	// reading owned-file events during that pass so a healthy target can run.
	queueWatchPath := func(name string) {
		if !legacyWatch && !debounceAllPaths && !debounceKeepFailedPaths {
			// A failed target keeps its retry deadline. When a healthy
			// target changes in the same burst, inspect it first rather
			// than waiting for the failed target's worker timeout.
			if failedOwnedPaths[filepath.Clean(name)] {
				if debounceHasHealthyPath {
					deferredFailedPaths, deferredFailedAll = enterpriseHookWatchAddTriggerPath(deferredFailedPaths, deferredFailedAll, name)
				} else {
					debouncePaths, debounceAllPaths = enterpriseHookWatchAddTriggerPath(debouncePaths, debounceAllPaths, name)
				}
			} else {
				if !debounceHasHealthyPath {
					var failed []string
					debouncePaths, failed = enterpriseHookWatchPartitionFailedPaths(debouncePaths, failedOwnedPaths)
					for _, path := range failed {
						deferredFailedPaths, deferredFailedAll = enterpriseHookWatchAddTriggerPath(deferredFailedPaths, deferredFailedAll, path)
					}
					debounceHasHealthyPath = true
				}
				debouncePaths, debounceAllPaths = enterpriseHookWatchAddTriggerPath(debouncePaths, debounceAllPaths, name)
			}
		} else {
			debouncePaths, debounceAllPaths = enterpriseHookWatchAddTriggerPath(debouncePaths, debounceAllPaths, name)
		}
		if !debouncePending {
			debounceArmedAt = time.Now()
		}
		delay := enterpriseHookWatchDebounceDelay(time.Now(), debounceArmedAt, enterpriseHookWatchDebounce, enterpriseHookWatchDebounceMaxWait)
		if debounceKeepFailedPaths {
			delay = 0
		}
		resetEnterpriseHookWatchTimer(debounce, delay)
		debouncePending = true
		debounceReason = "fsnotify"
	}
	handleWatchEvent := func(event fsnotify.Event) {
		event.Name = enterpriseHookWatchOwnedPath(event.Name, windowsOwnedPaths)
		if !enterpriseHookWatchEventRelevant(event) {
			return
		}
		lastTargetFailed := failedOwnedPaths[filepath.Clean(event.Name)]
		if legacyWatch {
			lastTargetFailed = legacyRepairRetryNeeded
		}
		drop, settling := enterpriseHookWatchEventDropped(time.Now(), settleUntil, event, lastTargetFailed,
			exclusiveOwned, sharedOwned, foundSnapshot, ownedSnapshot, enterpriseHookOwnedFileFingerprint, !legacyWatch)
		if drop {
			if settling {
				droppedInSettle++
			}
			return
		}
		if droppedInSettle > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] settled: suppressed %d self-write event(s) within %s of last reconcile\n", droppedInSettle, enterpriseHookWatchSettle)
			droppedInSettle = 0
		}
		if !legacyWatch && !failedOwnedPaths[filepath.Clean(event.Name)] && failedOwnedPaths[lastTriggerPath] {
			lastTriggerPath, lastTriggerOp = "", 0
		}
		lastTriggerPath, lastTriggerOp = enterpriseHookWatchNoteTrigger(lastTriggerPath, lastTriggerOp, event)
		queueWatchPath(event.Name)
	}
	// Reconcile on the watch loop, but consume owned-file events while it
	// runs. Only the watch loop updates retry and snapshot state.
	replayPending := false
	reconcileWatchPass := func(reason string) (bool, error) {
		if legacyWatch {
			_, err := reconcile(reason)
			return false, err
		}
		passCtx, cancel := context.WithCancel(cmd.Context())
		activeWorkers := newEnterpriseHookWatchActiveWorkers(previousRun)
		passCtx = context.WithValue(passCtx, enterpriseHookWatchActiveWorkersKey{}, activeWorkers)
		interrupted := make(chan fsnotify.Event, 1)
		stop := make(chan struct{})
		stopped := make(chan struct{})
		// The pump alone writes this map; the watch loop reads it after
		// stopped closes. Recheck a worker's event once the pass ends so a
		// concurrent account write cannot disappear into its final snapshot.
		activeEvents := map[string]fsnotify.Op{}
		owned := make(map[string]struct{}, len(exclusiveOwned)+len(sharedOwned))
		for path := range exclusiveOwned {
			owned[path] = struct{}{}
		}
		for path := range sharedOwned {
			owned[path] = struct{}{}
		}
		windowsPaths := windowsOwnedPaths
		priorExclusive, priorShared := maps.Clone(exclusiveOwned), maps.Clone(sharedOwned)
		priorFound, priorLeft := maps.Clone(foundSnapshot), maps.Clone(ownedSnapshot)
		priorFailed := maps.Clone(failedOwnedPaths)
		priorSettleUntil := settleUntil
		passWrites := &enterpriseHookWatchPassWrites{}
		go func() {
			defer close(stopped)
			for {
				select {
				case <-stop:
					return
				case event, ok := <-events.Events:
					if !ok {
						return
					}
					event.Name = enterpriseHookWatchOwnedPath(event.Name, windowsPaths)
					path := filepath.Clean(event.Name)
					if _, ok := owned[path]; !ok || !enterpriseHookWatchEventRelevant(event) {
						continue
					}
					if _, exclusive := priorExclusive[path]; exclusive {
						passWrites.observe(event, priorLeft)
					}
					// A late event for a completed repair is the worker's
					// tail only while the verified bytes remain in place.
					// A fresh change after the worker returns interrupts the
					// pass so that account is inspected promptly.
					workerActive, workerRepaired := activeWorkers.state(path)
					if workerActive || ((workerRepaired || activeEvents[path] != 0) &&
						enterpriseHookOwnedFileFingerprint(path) == priorLeft[path]) {
						activeEvents[path] |= event.Op
						continue
					}
					drop, _ := enterpriseHookWatchEventDropped(time.Now(), priorSettleUntil, event,
						priorFailed[path], priorExclusive, priorShared, priorFound, priorLeft,
						enterpriseHookOwnedFileFingerprint, true)
					if !drop {
						interrupted <- event
						cancel()
						return
					}
				}
			}
		}()
		_, err := reconcile(reason, context.WithValue(passCtx, enterpriseHookWatchPassWritesKey{}, passWrites))
		close(stop)
		<-stopped
		cancel()
		for path, op := range activeEvents {
			if before, known := priorLeft[path]; known && before != "absent" &&
				enterpriseHookOwnedFileFingerprint(path) != before {
				// The completed run may have snapped the remaining drift as
				// its new baseline. Keep the last verified fingerprint until
				// the queued pass has inspected and repaired this file.
				ownedSnapshot[path] = before
				lastTriggerPath, lastTriggerOp = enterpriseHookWatchNoteTrigger(lastTriggerPath, lastTriggerOp,
					fsnotify.Event{Name: path, Op: op})
				queueWatchPath(path)
				replayPending = true
			}
		}
		select {
		case event := <-interrupted:
			handleWatchEvent(event)
			if debouncePending {
				replayPending = true
			}
			return true, err
		default:
			return false, err
		}
	}

	// Events queued during a pass keep their filesystem attribution even
	// when another interval tick arrives before their debounce expires.
	intervalDeferred := false
	runIntervalPass := func() bool {
		if enterpriseHookStandaloneConfigChanged(standaloneConfigFingerprint, cmd.ErrOrStderr()) {
			return true
		}
		interrupted, err := reconcileWatchPass("interval")
		if err != nil && !errors.Is(err, context.Canceled) {
			logReconcileFailure("interval", err)
		}
		if interrupted {
			return false
		}
		hostChecks.Run()
		if repairRetryNeeded() {
			scheduleRepairRetry()
		} else {
			cancelRepairRetry()
			if legacyWatch || !replayPending {
				cancelPendingDebounce()
			}
		}
		return false
	}

	for {
		if intervalDeferred && !debouncePending {
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			intervalDeferred = false
			if runIntervalPass() {
				return nil
			}
		}
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
			handleWatchEvent(event)
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
				replayPending = false
				// If only a healthy path's event reached this loop, retain any
				// failed owned path whose current state differs from the last
				// reconcile. Save the old fingerprints now; check the files
				// after the healthy pass so those reads cannot delay its repair.
				var priorFailedSnapshot map[string]string
				if !legacyWatch && debounceHasHealthyPath {
					priorFailedSnapshot = make(map[string]string, len(failedOwnedPaths))
					for path := range failedOwnedPaths {
						priorFailedSnapshot[path] = ownedSnapshot[path]
					}
				}
				reason := debounceReason
				debounceReason = ""
				if reason == "" {
					reason = "fsnotify"
				}
				enterpriseHookReconcileRecheckWindow = enterpriseHookWatchRecheckFor(reason)
				passPaths, allPaths := debouncePaths, debounceAllPaths
				enterpriseHookReconcileRecheckPaths, enterpriseHookReconcileRecheckAll = debouncePaths, debounceAllPaths
				debouncePaths, debounceAllPaths = nil, false
				debounceHasHealthyPath = false
				debounceKeepFailedPaths = false
				interrupted, err := reconcileWatchPass(reason)
				enterpriseHookReconcileRecheckWindow = 0
				enterpriseHookReconcileRecheckPaths, enterpriseHookReconcileRecheckAll = nil, false
				for path, before := range priorFailedSnapshot {
					if failedOwnedPaths[path] && enterpriseHookOwnedFileFingerprint(path) != before {
						deferredFailedPaths, deferredFailedAll = enterpriseHookWatchAddTriggerPath(deferredFailedPaths, deferredFailedAll, path)
					}
				}
				// Windows can report a late Write for the healthy file just
				// restored by this pass. Its metadata fingerprint changes even
				// when its bytes are back. Replay that event, but include the
				// changed failed path already waiting behind it. A healthy
				// file that differs from this pass's snapshot still goes first.
				if runtime.GOOS == "windows" && !legacyWatch && debouncePending && (len(deferredFailedPaths) > 0 || deferredFailedAll) {
					var included bool
					debouncePaths, debounceAllPaths, included = enterpriseHookWatchIncludeDeferredFailed(
						debouncePaths, debounceAllPaths, deferredFailedPaths, deferredFailedAll, failedOwnedPaths,
						func(path string) bool {
							return enterpriseHookWatchOwnedFileChanged(path, exclusiveOwned, sharedOwned, ownedSnapshot, enterpriseHookOwnedFileFingerprint)
						},
					)
					if included {
						deferredFailedPaths, deferredFailedAll = nil, false
						debounceKeepFailedPaths = true
						resetEnterpriseHookWatchTimer(debounce, 0)
					}
				}
				if err != nil && !errors.Is(err, context.Canceled) {
					logReconcileFailure(reason, err)
				}
				if interrupted {
					// An interrupted pass did not publish its result. Preserve
					// its original paths alongside the event that preempted it.
					if allPaths {
						if debounceHasHealthyPath {
							deferredFailedAll = true
						} else {
							debounceAllPaths = true
							if !debouncePending {
								debounceArmedAt = time.Now()
								resetEnterpriseHookWatchTimer(debounce, 0)
								debouncePending = true
								debounceReason = "fsnotify"
							}
						}
					} else {
						for _, path := range passPaths {
							queueWatchPath(path)
						}
					}
				}
				if allPaths && !interrupted && err == nil {
					deferredFailedPaths, deferredFailedAll = nil, false
				}
				if !debouncePending && (len(deferredFailedPaths) > 0 || deferredFailedAll) {
					debouncePaths, debounceAllPaths = deferredFailedPaths, deferredFailedAll
					deferredFailedPaths, deferredFailedAll = nil, false
					debounceArmedAt = time.Now()
					resetEnterpriseHookWatchTimer(debounce, 0)
					debouncePending = true
					debounceReason = "fsnotify"
				}
				if interrupted {
					continue
				}
				if repairRetryNeeded() {
					scheduleRepairRetry()
				} else {
					cancelRepairRetry()
				}
			}
		case <-repairRetry.C:
			repairRetryPending = false
			repairRetryDue = time.Time{}
			if legacyWatch {
				if _, err := reconcile("retry"); err != nil {
					logReconcileFailure("retry", err)
				}
			} else {
				interrupted, err := reconcileWatchPass("retry")
				if err != nil && !errors.Is(err, context.Canceled) {
					logReconcileFailure("retry", err)
				}
				if interrupted {
					continue
				}
			}
			if debouncePending && !legacyWatch {
				// The owned-file pass that interrupted this retry goes first.
				continue
			}
			if repairRetryNeeded() {
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
		case <-intervalTicks:
			if !legacyWatch && replayPending && debouncePending {
				intervalDeferred = true
				continue
			}
			if runIntervalPass() {
				return nil
			}
		}
	}
}

type enterpriseHookWatchPassWritesKey struct{}

type enterpriseHookWatchActiveWorkersKey struct{}

// The watch pump must not cancel a pass for a write made by one of that
// pass's workers, even if its first event arrives after the worker returns.
// It still preempts a slow pass for a changed file in another account.
type enterpriseHookWatchActiveWorkers struct {
	mu         sync.RWMutex
	owners     map[string][]string
	targetKeys map[string]string
	active     map[string]int
	repaired   map[string]bool
}

func newEnterpriseHookWatchActiveWorkers(prior enterpriseHookReconcileRun) *enterpriseHookWatchActiveWorkers {
	w := &enterpriseHookWatchActiveWorkers{
		owners: prior.WatchPathOwners, targetKeys: make(map[string]string, len(prior.Rows)),
	}
	for _, row := range prior.Rows {
		home, connector := row.UserHome, row.Connector
		if row.Result != nil {
			if home == "" {
				home = row.Result.UserHome
			}
			if connector == "" {
				connector = row.Result.Connector
			}
		}
		if id, key := enterpriseHookWatchTargetID(home, connector), enterpriseHookProtectedTargetKey(row); id != "" && key != "" {
			w.targetKeys[id] = key
		}
	}
	return w
}

func enterpriseHookWatchTargetID(home, connector string) string {
	if strings.TrimSpace(home) == "" || strings.TrimSpace(connector) == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(connector)) + "\x00" + filepath.Clean(home)
}

func (w *enterpriseHookWatchActiveWorkers) state(path string) (active, repaired bool) {
	path = filepath.Clean(path)
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, key := range w.owners[path] {
		active = active || w.active[key] > 0
		repaired = repaired || w.repaired[key]
	}
	return active, repaired
}

// enterpriseHookWatchPassWrites records owned files observed with bytes or
// mode different from the last verified snapshot while a pass is running.
// A timestamp-only event or a same-content write is not a repair.
type enterpriseHookWatchPassWrites struct {
	mu    sync.Mutex
	paths map[string]bool
}

func (w *enterpriseHookWatchPassWrites) observe(event fsnotify.Event, verified map[string]string) {
	if !enterpriseHookWatchEventRelevant(event) {
		return
	}
	path := filepath.Clean(event.Name)
	want, known := verified[path]
	if !known || enterpriseHookOwnedFileFingerprint(path) == want {
		return
	}
	w.mu.Lock()
	if w.paths == nil {
		w.paths = make(map[string]bool)
	}
	w.paths[path] = true
	w.mu.Unlock()
	enterpriseHookWatchObservedDrift(path)
}

func (w *enterpriseHookWatchPassWrites) snapshot() map[string]bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return maps.Clone(w.paths)
}

// enterpriseHookWatchRestoredOwnedFiles reports files that return to the
// last pass's verified bytes and mode. An in-pass change also needs a repair
// reported by that file's owner; observing a brief changed fingerprint during
// an unrelated write is not enough. A first install and a failed repair do
// not qualify.
func enterpriseHookWatchRestoredOwnedFiles(prior enterpriseHookReconcileRun, verified, before, after map[string]string,
	observedDrift, repairedTargets map[string]bool, owned []string) []string {
	verifiedTargets := make(map[string]bool, len(prior.Rows))
	for _, row := range prior.Rows {
		if row.OK {
			verifiedTargets[enterpriseHookProtectedTargetKey(row)] = true
		}
	}
	var restored []string
	for _, name := range owned {
		path := filepath.Clean(name)
		verifiedOwner, reportedRepair := false, false
		for _, owner := range prior.WatchPathOwners[path] {
			if verifiedTargets[owner] {
				verifiedOwner = true
				reportedRepair = reportedRepair || repairedTargets[owner]
			}
		}
		if !verifiedOwner {
			continue
		}
		want, known := verified[path]
		if !known || want == "absent" || want == "unreadable" || strings.HasPrefix(want, "irregular:") {
			continue
		}
		found, checked := before[path]
		if !checked || after[path] != want ||
			(found == want && (!observedDrift[path] || !reportedRepair)) {
			continue
		}
		restored = append(restored, path)
	}
	slices.Sort(restored)
	return slices.Compact(restored)
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

// enterpriseHookWatchEventDropped reports whether the watch loop drops a
// filesystem event instead of arming a pass (drop), and whether it counts as
// a settle-window tail of the last pass (settling). lastPassFailed describes
// the target that owns this path, not an unrelated target in the same pass.
//
// A Write or Chmod in the settle window is the tail of the pass's own writes,
// and an event on an unowned path is noise, unless the owned file no longer
// holds what the last pass left there: an in-place overwrite of the scoped
// token right after a pass waited for the interval pass (GAP-0044), as did an
// in-place rewrite of a shared agent config (GAP-0045).
//
// A Create, Remove or Rename of an exclusive-writer file in the settle window
// that left the file as the pass found it and as it left it is the pass's own
// make-and-drop tail (a backup receipt a failed repair rolled back): it does
// not arm another pass, so the repair backoff applies (GAP-0030). That holds
// only after a failed pass. After a pass that succeeded, both snapshots of a
// hook file deleted again right after the pass repaired it say "absent" (the
// delete landed before the snapshot), so the delete was dropped as the pass's
// tail and the file stayed missing until the interval pass, 20-70 s after a
// held delete ended (GAP-0256).
func enterpriseHookWatchEventDropped(
	now, settleUntil time.Time,
	event fsnotify.Event,
	lastPassFailed bool,
	exclusiveOwned, sharedOwned map[string]struct{},
	found, left map[string]string,
	fingerprint func(string) string,
	replayDuringPass bool,
) (drop, settling bool) {
	actionable := enterpriseHookWatchOwnedEventActionable(event, exclusiveOwned, sharedOwned)
	settling = actionable && enterpriseHookWatchEventInSettleWindow(now, settleUntil, event.Op)
	if !settling && actionable && lastPassFailed &&
		enterpriseHookWatchExclusiveTailUnchanged(now, settleUntil, event, exclusiveOwned, found, left, fingerprint) {
		settling = true
	}
	// An event queued while a reconcile was running can arrive after its
	// final snapshot. If another target was in retry, the healthy target
	// may have been checked before its token was overwritten; the snapshot
	// then contains the damaged bytes. Replay that event once even though
	// the current file still matches the final snapshot. A later pass with
	// equal found/left snapshots drops any remaining self-write tail.
	changedDuringPass := replayDuringPass && !lastPassFailed && event.Op&(fsnotify.Write|fsnotify.Chmod) != 0 &&
		enterpriseHookWatchOwnedFileChangedBetweenSnapshots(event.Name, found, left)
	if (!actionable || settling) && !changedDuringPass &&
		!enterpriseHookWatchOwnedFileChanged(event.Name, exclusiveOwned, sharedOwned, left, fingerprint) {
		return true, settling
	}
	return false, settling
}

func enterpriseHookWatchOwnedFileChangedBetweenSnapshots(path string, found, left map[string]string) bool {
	path = filepath.Clean(path)
	before, foundOK := found[path]
	after, leftOK := left[path]
	return foundOK && leftOK && before != after
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
	for _, path := range run.RestoredPaths {
		triggerTag += fmt.Sprintf(" repair_path=%q", path)
	}
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
			if row.OK || row.Pending || row.Removed {
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

// The state file persists the transition marker, so interval and retry
// passes report a confirmed removal only once. A later enrollment under the
// same name gets a new live row and can be removed again in a later pass.
func logEnterpriseHookRemovedTransitions(writer io.Writer, previous, current []enterpriseHookReconcileRow) []enterpriseHookReconcileRow {
	seen := make(map[string]bool, len(previous))
	for _, row := range previous {
		if row.Removed {
			seen[enterpriseHookProtectedTargetKey(row)] = true
		}
	}
	var removed []enterpriseHookReconcileRow
	for _, row := range current {
		key := enterpriseHookProtectedTargetKey(row)
		if !row.Removed || seen[key] {
			continue
		}
		seen[key] = true
		removed = append(removed, row)
		fmt.Fprintf(writer, "[hook-guardian] target %s removed: account or profile no longer exists\n",
			enterpriseHookReconcileLogDetail(enterpriseHookReconcileRowLabel(row)))
	}
	return removed
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

// Windows directory events use the stored filename spelling. Keep the watch
// loop's path keys aligned with its owned-file lists for standalone installs.
func enterpriseHookWatchCaseFoldedOwnedPaths(exclusiveOwned, sharedOwned map[string]struct{}) map[string]string {
	paths := make(map[string]string, len(exclusiveOwned)+len(sharedOwned))
	for path := range sharedOwned {
		paths[strings.ToLower(filepath.Clean(path))] = path
	}
	for path := range exclusiveOwned {
		paths[strings.ToLower(filepath.Clean(path))] = path
	}
	return paths
}

func enterpriseHookWatchOwnedPath(path string, caseFolded map[string]string) string {
	if len(caseFolded) == 0 {
		return path
	}
	if owned, ok := caseFolded[strings.ToLower(filepath.Clean(path))]; ok {
		return owned
	}
	return path
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

// The watch-loop regression can wait until the pass has recorded a changed
// owned file before its test worker restores that file.
var enterpriseHookWatchObservedDrift = func(string) {}

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
			managed.GatewayServiceAccount(),
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
		managed.GatewayServiceAccount(),
	); err != nil {
		return fmt.Errorf("enterprise hooks: data_dir trust check failed: %w", err)
	}
	// Repair the guardian ledger before the first read of this run. A
	// drifted ledger otherwise fails every target and, at startup, the
	// whole service.
	ledgerRepairErr := repairEnterpriseHookGuardianLedger(cfg.DataDir)
	if err := managed.ValidateTrustedRuntimeDir(managed.HookGuardianAuthorizationDir(cfg.DataDir), "hook guardian authorization directory"); err != nil {
		return fmt.Errorf(
			"enterprise hooks: authorization directory trust check failed: %w",
			errors.Join(err, ledgerRepairErr),
		)
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
// guardian publishes together: its state, the protected authorization and
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
// reconcile. The guardian republishes them when a pass changes the outcome and
// at least every few minutes, and a status or verify
// that read in the middle of a publication failed although the guardian was healthy
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
		if row.Removed && (row.OK || row.Pending || row.Result != nil || !row.RevokeProtection || strings.TrimSpace(row.Error) == "") {
			return fmt.Errorf("hook guardian removed row has an inconsistent disposition")
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
	nowTime := time.Now().UTC()
	now := nowTime.Format(time.RFC3339Nano)
	previous, _, err := loadEnterpriseHookGuardianAuthorization(dataDir)
	if err != nil {
		return err
	}
	protected := mergeProtectedEnterpriseHookTargets(previous.ProtectedTargets, rows)
	healthy := complete && failures == 0 && successes+pending == len(rows)
	authorization := enterpriseHookGuardianAuthorization{
		Version:          1,
		UpdatedAt:        now,
		OK:               healthy,
		TargetCount:      len(rows),
		SuccessCount:     successes,
		FailureCount:     failures,
		PendingCount:     pending,
		ProtectedTargets: protected,
	}
	state := enterpriseHookGuardianState{
		Version:      1,
		UpdatedAt:    now,
		Manifest:     strings.TrimSpace(manifest),
		OK:           healthy,
		TargetCount:  len(rows),
		SuccessCount: successes,
		FailureCount: failures,
		PendingCount: pending,
		Results:      rows,
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
		OK:               healthy,
		TargetCount:      len(rows),
		SuccessCount:     successes,
		FailureCount:     failures,
		PendingCount:     pending,
		ProtectedTargets: protected,
	}

	authorizationDir, err := prepareEnterpriseHookAuthorizationDir(dataDir)
	if err != nil {
		return err
	}
	// An unchanged outcome keeps its published generation once this process
	// has published one: the three records stay as they are, so a status
	// reader never meets a rewrite for a pass that decided nothing new
	// (GAP-0912). The first pass of every guardian process always publishes,
	// because a restart is proved by a new generation (Setup waits for a
	// reconcile ID it has not seen, GAP-0931). A changed outcome, a record
	// that does not read back as trusted and coherent, and a generation old
	// enough to near the freshness limit are republished as well.
	if enterpriseHookGuardianPublishedByProcess.Load() &&
		enterpriseHookGuardianGenerationCurrent(dataDir, nowTime, authorization, state, activation) {
		return nil
	}
	authorizationData, err := json.MarshalIndent(authorization, "", "  ")
	if err != nil {
		return err
	}
	authorizationData = append(authorizationData, '\n')
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
			managed.GatewayServiceAccount(),
		); err != nil {
			return err
		}
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
	enterpriseHookGuardianPublishedByProcess.Store(true)
	return nil
}

// enterpriseHookGuardianPublishedByProcess is set once this process has
// published a complete generation. Until then no pass may keep a generation
// an earlier process wrote: a consumer that restarts the guardian and waits
// for a reconcile it has not seen would never get one.
var enterpriseHookGuardianPublishedByProcess atomic.Bool

// enterpriseHookGuardianRepublishAfter is how old an unchanged generation of
// the guardian records may get before the guardian publishes it again. The
// readers refuse records older than managed.HookGuardianMaxAge, and the guardian
// reconciles at least once a minute, so half of that limit keeps the records
// fresh with room for a missed pass.
const enterpriseHookGuardianRepublishAfter = managed.HookGuardianMaxAge / 2

// enterpriseHookGuardianGenerationCurrent reports whether the records on disk
// already say what this pass decided: the three read back trusted, name one
// generation, are younger than enterpriseHookGuardianRepublishAfter and
// match the candidates in everything but the generation stamp (timestamp and
// reconcile ID). When it reports true it has not written anything.
func enterpriseHookGuardianGenerationCurrent(
	dataDir string,
	now time.Time,
	authorization enterpriseHookGuardianAuthorization,
	state enterpriseHookGuardianState,
	activation enterpriseHookGuardianActivation,
) bool {
	publishedState, exists, err := loadEnterpriseHookGuardianState(dataDir)
	if err != nil || !exists {
		return false
	}
	publishedAuthorization, exists, err := loadEnterpriseHookGuardianAuthorization(dataDir)
	if err != nil || !exists {
		return false
	}
	publishedActivation, exists, err := loadEnterpriseHookGuardianActivation(dataDir)
	if err != nil || !exists {
		return false
	}
	if publishedState.UpdatedAt != publishedAuthorization.UpdatedAt ||
		publishedActivation.UpdatedAt != publishedAuthorization.UpdatedAt {
		return false
	}
	stamped, err := time.Parse(time.RFC3339Nano, publishedActivation.UpdatedAt)
	if err != nil || stamped.After(now) || now.Sub(stamped) >= enterpriseHookGuardianRepublishAfter {
		return false
	}
	// The loaders hand back an empty list where the writer had none.
	canonical := func(rows []enterpriseHookReconcileRow) []enterpriseHookReconcileRow {
		if rows == nil {
			return []enterpriseHookReconcileRow{}
		}
		return rows
	}
	authorization.UpdatedAt = publishedAuthorization.UpdatedAt
	authorization.ProtectedTargets = canonical(authorization.ProtectedTargets)
	publishedAuthorization.ProtectedTargets = canonical(publishedAuthorization.ProtectedTargets)
	state.UpdatedAt = publishedState.UpdatedAt
	state.Results = canonical(state.Results)
	publishedState.Results = canonical(publishedState.Results)
	activation.UpdatedAt, activation.ReconcileID = publishedActivation.UpdatedAt, publishedActivation.ReconcileID
	activation.ProtectedTargets = canonical(activation.ProtectedTargets)
	publishedActivation.ProtectedTargets = canonical(publishedActivation.ProtectedTargets)
	return sameEnterpriseHookRecord(authorization, publishedAuthorization) &&
		sameEnterpriseHookRecord(state, publishedState) &&
		sameEnterpriseHookRecord(activation, publishedActivation)
}

// sameEnterpriseHookRecord compares two records by what they serialize to,
// which is what a reader of the file sees.
func sameEnterpriseHookRecord(a, b any) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
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

// enterpriseHookDeferredFirstEnrollment reports the first enrollment of a
// deferred row the guardian never protected: an account that stayed pending
// while it was signed out. Only that enrollment may move aside the
// account's own link at its DefenseClaw folder (GAP-0193); a repair of a
// protected account and any row that is not deferred refuse it.
func enterpriseHookDeferredFirstEnrollment(target enterprisehooks.ManifestTarget, previous enterpriseHookPreviousProtection) bool {
	return target.IsDeferred() && !previous.PreviouslyProtected
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
	// An unresolved profile has no home; filepath.Clean would turn "" into
	// "." and the SID match would then never find the ledger row.
	if userHome = strings.TrimSpace(userHome); userHome != "" {
		userHome = filepath.Clean(userHome)
	}
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

// previousEnterpriseHookSuccess reports whether the ledger records the target
// as protected. The reconcile uses it to look up a target whose profile no
// longer resolves by its manifest identity.
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
	data, exists, err := readEnterpriseHookPublishedRecord(
		path,
		"hook guardian authorization",
		enterpriseHookGuardianAuthorizationMaxBytes,
		enterpriseHookAuthorizationFileTrustCheck,
	)
	if err != nil || !exists {
		return enterpriseHookGuardianAuthorization{}, exists, err
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
	data, exists, err := readEnterpriseHookPublishedRecord(
		path,
		"hook guardian activation",
		enterpriseHookGuardianAuthorizationMaxBytes,
		enterpriseHookAuthorizationFileTrustCheck,
	)
	if err != nil || !exists {
		return enterpriseHookGuardianActivation{}, exists, err
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
		return nil, fmt.Errorf("%s changed identity before open: %w", label, safefile.ErrReadIdentityChanged)
	}
	if openedInfo.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", label, maxBytes)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(openedInfo, current) {
		return nil, fmt.Errorf("%s changed identity before read: %w", label, safefile.ErrReadIdentityChanged)
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

// readEnterpriseHookPublishedRecord reads a machine-owned guardian record that
// the guardian replaces atomically while a status, verify or ensure reader
// looks at it. The whole sequence (name check, trust check, open, identity
// check, read) is one attempt; a replacement between its steps, or a sharing
// violation while the record is swapped in, repeats the attempt with the same
// bounded policy as the other validated managed reads (GAP-0655,
// safefile.RetryPublishedRead). Only those transient results repeat: a
// record that stays swapped fails closed after the bound, naming the file; a
// link, a file of another type or a failed trust check (owner, ACL) is
// refused at once. A record that is missing on the first look is reported as
// absent, not as an error; one that was seen and then goes missing is a
// replacement in flight and is never reported as absent. trust may be nil.
func readEnterpriseHookPublishedRecord(path, label string, maxBytes int64, trust func(string) error) ([]byte, bool, error) {
	var data []byte
	exists := false
	observed := false
	err := safefile.RetryPublishedRead(func() error {
		data, exists = nil, false
		info, err := pathidentity.LstatPinned(path)
		if errors.Is(err, os.ErrNotExist) {
			if observed {
				// The record was there on an earlier attempt of this read. A
				// name that is missing now is a replacement in flight: repeat,
				// and fail closed naming the record if it never returns. It
				// must not turn into silent absence.
				exists = true
				return fmt.Errorf("%s disappeared while it was being replaced: %s: %w", label, path, safefile.ErrReadIdentityChanged)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect %s %s: %w", label, path, err)
		}
		exists, observed = true, true
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file: %s", label, path)
		}
		if trust != nil {
			if err := trust(path); err != nil {
				return err
			}
		}
		read, err := readEnterpriseHookBoundedFile(path, info, maxBytes, label)
		if errors.Is(err, os.ErrNotExist) && !errors.Is(err, safefile.ErrReadIdentityChanged) {
			// The name was checked a moment ago; it is being replaced.
			err = fmt.Errorf("%w: %w", err, safefile.ErrReadIdentityChanged)
		}
		if err != nil {
			return fmt.Errorf("read %s %s: %w", label, path, err)
		}
		data = read
		return nil
	})
	return data, exists, err
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
		if row.RevokeProtection || row.Removed {
			continue
		}
		if prior, ok := previousByKey[key]; ok {
			merged[key] = prior
			continue
		}
		// A ledger row written before platform identities existed has no SID
		// and is keyed by user name; carry it forward under the current
		// identity so the first failed repair after an upgrade keeps it.
		for _, prior := range previous {
			if prior.OK && strings.TrimSpace(prior.SID) == "" &&
				strings.EqualFold(strings.TrimSpace(prior.Connector), strings.TrimSpace(row.Connector)) &&
				enterpriseHookLegacyLedgerRowMatchesPlatform(prior, row.User, row.UserHome, row.SID) {
				prior.SID = row.SID
				merged[key] = prior
				break
			}
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
	if rowSID == "" && enterpriseHookLegacyLedgerRowMatchesPlatform(row, userName, userHome, sid) {
		return true
	}
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
	if target.sid == "" {
		// Where accounts have a stable identity beyond the short name, key
		// the ledger on it so a reused name never inherits protection.
		identity, err := enterpriseHookPlatformTargetIdentity(strings.TrimSpace(userName), target.uid)
		if err != nil {
			return target, err
		}
		target.sid = identity
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
