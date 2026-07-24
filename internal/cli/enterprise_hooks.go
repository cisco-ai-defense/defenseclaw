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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

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

	enterpriseHooksRuntimeGOOS                 = func() string { return runtime.GOOS }
	enterpriseHooksPlatformPreflight           = enterpriseHooksNativePlatformPreflight
	enterpriseHooksRootPersistentPreRun        = rootPersistentPreRunE
	enterpriseHooksInstallRunE                 = runEnterpriseHooksInstall
	enterpriseHooksUninstallRunE               = runEnterpriseHooksUninstall
	enterpriseHooksReconcileRunE               = runEnterpriseHooksReconcile
	enterpriseHooksWatchRunE                   = runEnterpriseHooksWatch
	enterpriseHookAuthorizationOwnershipSetter = setEnterpriseHookAuthorizationOwnership
	enterpriseHooksRemoveManagedPolicy         = enterprisehooks.RemoveManagedPolicy
)

const defaultEnterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
const hookGuardianStateFile = "hook_guardian_state.json"
const hookGuardianAuthorizationFile = managed.HookGuardianAuthorizationFile
const hookGuardianAuthorizationDirEnv = managed.HookGuardianAuthorizationDirEnv

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

var enterpriseHooksInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install or repair a hook-native connector for one interactive user",
	Long: `Install or repair DefenseClaw hook wiring for one interactive user's
agent configuration.

The hardened gateway service should not be granted write access to /home.
Instead, run this command as an administrator for each protected user, or from
a systemd timer/MDM guardian. First-time installs require the agent's native
hook config file to already exist, so broad process discovery cannot create a
new app profile from scratch.`,
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
		"Administrator-managed connector to remove (currently claudecode on native Windows)")
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

	enterpriseHooksCmd.AddCommand(enterpriseHooksInstallCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksUninstallCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksReconcileCmd)
	enterpriseHooksCmd.AddCommand(enterpriseHooksWatchCmd)
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
	token, err := enterpriseHookScopedToken(cfg.DataDir, enterpriseHookConnector)
	if err != nil {
		return enterpriseHooksInstallError(cmd, err)
	}
	otlpToken, err := enterpriseHookScopedOTLPToken(cfg.DataDir, enterpriseHookConnector)
	if err != nil {
		return enterpriseHooksInstallError(cmd, err)
	}

	opts := enterprisehooks.InstallOptions{
		ConnectorName:                enterpriseHookConnector,
		UserHome:                     target.home,
		OwnerUID:                     target.uid,
		OwnerGID:                     target.gid,
		OwnerSID:                     target.sid,
		DataDir:                      enterpriseHookDataDir,
		APIAddr:                      apiAddr,
		ProxyAddr:                    proxyAddr,
		APIToken:                     token,
		OTLPPathToken:                otlpToken,
		HookFailMode:                 cfg.EffectiveHookFailModeForConnector(enterpriseHookConnector),
		GuardrailMode:                cfg.EffectiveGuardrailModeForConnector(enterpriseHookConnector),
		HILTEnabled:                  cfg.EffectiveHILTForConnector(enterpriseHookConnector).Enabled,
		AgentVersion:                 enterpriseHookAgentVersion,
		WorkspaceDir:                 cfg.ConnectorWorkspaceDir(),
		Registry:                     newConnectorRegistryWithPlugins(),
		AllowMissingHookConfigRepair: previousEnterpriseHookSuccess(cfg.DataDir, enterpriseHookUser, target.home, enterpriseHookConnector),
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
	WatchSharedFiles    []string // agent + DC writers: react only to Remove/Rename
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

func runEnterpriseHookReconcileOnce(ctx context.Context) (enterpriseHookReconcileRun, error) {
	run := enterpriseHookReconcileRun{Manifest: enterpriseHookManifest}
	if cfg == nil {
		return run, fmt.Errorf("enterprise hooks reconcile: config is not loaded")
	}
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
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
	registry := newConnectorRegistryWithPlugins()

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
			Connector: strings.TrimSpace(target.Connector),
		}
		token := ""
		otlpToken := ""
		resolved, err := resolveEnterpriseHookTargetValues(target.User, target.UserHome, intPtrValue(target.UID), intPtrValue(target.GID), target.SID, target.DataDir)
		if err == nil {
			var tokenErr error
			token, tokenErr = enterpriseHookScopedToken(cfg.DataDir, target.Connector)
			if tokenErr != nil {
				err = tokenErr
			}
		}
		if err == nil {
			var tokenErr error
			otlpToken, tokenErr = enterpriseHookScopedOTLPToken(cfg.DataDir, target.Connector)
			if tokenErr != nil {
				err = tokenErr
			}
		}
		if err == nil {
			opts := enterprisehooks.InstallOptions{
				ConnectorName:                target.Connector,
				UserHome:                     resolved.home,
				OwnerUID:                     resolved.uid,
				OwnerGID:                     resolved.gid,
				OwnerSID:                     resolved.sid,
				DataDir:                      strings.TrimSpace(target.DataDir),
				APIAddr:                      apiAddr,
				ProxyAddr:                    proxyAddr,
				APIToken:                     token,
				OTLPPathToken:                otlpToken,
				HookFailMode:                 cfg.EffectiveHookFailModeForConnector(target.Connector),
				GuardrailMode:                cfg.EffectiveGuardrailModeForConnector(target.Connector),
				HILTEnabled:                  cfg.EffectiveHILTForConnector(target.Connector).Enabled,
				AgentVersion:                 strings.TrimSpace(target.AgentVersion),
				WorkspaceDir:                 cfg.ConnectorWorkspaceDir(),
				Registry:                     registry,
				AllowMissingHookConfigRepair: previousEnterpriseHookSuccess(cfg.DataDir, target.User, resolved.home, target.Connector),
			}
			if dirs, watchErr := enterprisehooks.WatchDirs(opts); watchErr == nil {
				for _, dir := range dirs {
					watchDirs[dir] = struct{}{}
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
			var result enterprisehooks.InstallResult
			result, err = enterprisehooks.Install(ctx, opts)
			if err == nil {
				row.OK = true
				row.UserHome = result.UserHome
				row.Connector = result.Connector
				row.Result = &result
			}
		}
		if err != nil {
			failures++
			row.OK = false
			row.Error = err.Error()
		}
		rows = append(rows, row)
	}

	stateErr := writeEnterpriseHookGuardianState(cfg.DataDir, enterpriseHookManifest, rows, failures)
	run.Rows = rows
	run.Failures = failures
	run.StateErr = stateErr
	run.WatchDirs = sortedEnterpriseHookWatchDirs(watchDirs)
	run.WatchExclusiveFiles = sortedEnterpriseHookWatchDirs(exclusiveFiles)
	run.WatchSharedFiles = sortedEnterpriseHookWatchDirs(sharedFiles)
	return run, nil
}

func runEnterpriseHooksWatch(cmd *cobra.Command, _ []string) error {
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
	sharedOwned := map[string]struct{}{}    // agent + DC writers — only Remove/Rename triggers
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
	//                    every fsnotify event observed immediately
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
	reconcile := func(reason string) (bool, error) {
		run, err := runEnterpriseHookReconcileOnce(cmd.Context())
		if err != nil {
			return false, err
		}
		dirs := append([]string{filepath.Dir(filepath.Clean(enterpriseHookManifest))}, run.WatchDirs...)
		syncEnterpriseHookWatchDirs(cmd, fsw, watched, dirs)
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
		// When the row set is byte-identical to the previous run,
		// any Write/Chmod events still leaking past the normal
		// settle window are tail-writes from our own reconcile
		// (macOS FSEvents can batch chmod with 3-5 s latency).
		// Widen the settle window modestly — enough to cover
		// FSEvents batching, NOT enough to swallow a real subsequent
		// tamper. Cap at 3x settle so the widened window stays in
		// seconds, not minutes. Remove/Rename events are exempt from
		// suppression by enterpriseHookWatchEventInSettleWindow, so
		// widening the window here does not risk missing a "user
		// deleted the hook config" event even if the previous
		// reconcile classified as no_change.
		settle := enterpriseHookWatchSettle
		if !changed {
			settle = enterpriseHookWatchSettle * 3
		}
		settleUntil = time.Now().Add(settle)
		droppedInSettle = 0
		return changed, nil
	}

	if _, err := reconcile("startup"); err != nil {
		return err
	}

	ticker := time.NewTicker(enterpriseHookWatchInterval)
	defer ticker.Stop()
	debounce := time.NewTimer(time.Hour)
	if !debounce.Stop() {
		<-debounce.C
	}
	debouncePending := false

	for {
		select {
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		case event, ok := <-fsw.Events:
			if !ok {
				return nil
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
			//     rewrites these during normal use. Only Remove /
			//     Rename is a real tamper signal; Write and Chmod are
			//     the agent doing its own thing and the 5-min backstop
			//     handles any in-place stripping.
			//
			// Events on unowned paths (agent session state, sqlite
			// WAL churn, cache writes, workspace snapshots) are
			// silently dropped — no log, no debounce — because they
			// happen continuously and previously dominated the log.
			//
			// Empty maps means we haven't run a reconcile yet (only
			// possible pre-startup); fall through so the startup
			// reconcile flow is unaffected.
			if len(exclusiveOwned) > 0 || len(sharedOwned) > 0 {
				cleaned := filepath.Clean(event.Name)
				_, isExclusive := exclusiveOwned[cleaned]
				_, isShared := sharedOwned[cleaned]
				if !isExclusive && !isShared {
					continue
				}
				if isShared && !isExclusive {
					// Shared-writer file: skip Write and Chmod events
					// entirely — the agent is updating its own
					// unrelated state. Any Remove/Rename falls
					// through to the settle/reconcile path below.
					if event.Op&(fsnotify.Remove|fsnotify.Rename) == 0 {
						continue
					}
				}
			}
			// Drop events observed inside the post-reconcile settle
			// window: they are almost certainly the tail of writes the
			// reconcile itself just made (chmod / state file rewrite,
			// or a rename that macOS surfaces as REMOVE on the
			// destination — see enterpriseHookWatchEventInSettleWindow
			// for the design rationale).
			//
			// Exception: a Remove/Rename observation inside the window
			// where the file is ACTUALLY missing on disk is a real
			// user tamper that raced with our reconcile, not our own
			// atomic-write tail. rename(2) atomically replaces the
			// destination so the file is present immediately after —
			// a Stat call ~microseconds after the fsnotify event
			// distinguishes the two cases deterministically. Without
			// this carve-out, back-to-back user tampers get eaten by
			// the previous tamper's widened settle window.
			if enterpriseHookWatchEventInSettleWindow(time.Now(), settleUntil, event.Op) {
				if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
					if _, statErr := os.Lstat(event.Name); os.IsNotExist(statErr) {
						// File genuinely gone — real user rm, fall
						// through and reconcile.
					} else {
						droppedInSettle++
						continue
					}
				} else {
					droppedInSettle++
					continue
				}
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
		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] fsnotify error: %s\n", err)
		case <-debounce.C:
			if debouncePending {
				debouncePending = false
				if _, err := reconcile("fsnotify"); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] reconcile after fsnotify failed: %s\n", err)
				}
			}
		case <-ticker.C:
			if _, err := reconcile("interval"); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] interval reconcile failed: %s\n", err)
			}
		}
	}
}

// enterpriseHookWatchEventInSettleWindow reports whether an fsnotify
// event observed at now should be suppressed because it lands inside
// the post-reconcile settle window. A zero settleUntil (never
// reconciled yet, or explicitly disabled) always returns false: never
// suppress.
//
// All event ops (Write, Chmod, Remove, Rename) are suppressed inside
// the window. The guardian's Install pass writes files via a
// tempfile+rename dance (atomicWriteFile → os.Rename), and on macOS
// rename(2) over an existing destination fires an fsnotify REMOVE
// event on the destination path. So a REMOVE observed within the
// settle window is our own atomic-write finishing, not a user
// tamper. Real user Removes happen outside the settle window and
// still trigger reconcile promptly (worst case: settle window
// duration, default 2 s).
func enterpriseHookWatchEventInSettleWindow(now, settleUntil time.Time, op fsnotify.Op) bool {
	if settleUntil.IsZero() {
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

func enterpriseHookWatchEventRelevant(event fsnotify.Event) bool {
	if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove|fsnotify.Chmod) == 0 {
		return false
	}
	return !strings.HasSuffix(filepath.Base(event.Name), ".lock")
}

func syncEnterpriseHookWatchDirs(cmd *cobra.Command, fsw *fsnotify.Watcher, watched map[string]struct{}, dirs []string) {
	next := map[string]struct{}{}
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
			fmt.Fprintf(cmd.ErrOrStderr(), "[hook-guardian] watch %s failed: %s\n", dir, err)
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
	if err := managed.ValidateTrustedRuntimeDir(cfg.DataDir, "hook guardian state data_dir"); err != nil {
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
	protected := mergeProtectedEnterpriseHookTargets(loadProtectedEnterpriseHookTargets(dataDir), rows)
	authorization := enterpriseHookGuardianAuthorization{
		Version:          1,
		UpdatedAt:        now,
		ProtectedTargets: protected,
	}
	authorizationData, err := json.MarshalIndent(authorization, "", "  ")
	if err != nil {
		return err
	}
	authorizationData = append(authorizationData, '\n')
	authorizationDir := managed.HookGuardianAuthorizationDir(dataDir)
	if err := os.MkdirAll(authorizationDir, 0o750); err != nil {
		return fmt.Errorf("create hook guardian authorization directory: %w", err)
	}
	if err := os.Chmod(authorizationDir, 0o750); err != nil {
		return fmt.Errorf("harden hook guardian authorization directory: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(authorizationDir); err != nil {
		return fmt.Errorf("set hook guardian authorization directory ownership: %w", err)
	}
	authorizationPath := filepath.Join(authorizationDir, hookGuardianAuthorizationFile)
	if err := safefile.Write(authorizationPath, authorizationData); err != nil {
		return fmt.Errorf("write %s: %w", authorizationPath, err)
	}
	if err := os.Chmod(authorizationPath, 0o640); err != nil {
		return fmt.Errorf("make hook guardian authorization readable: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(authorizationPath); err != nil {
		return fmt.Errorf("set hook guardian authorization file ownership: %w", err)
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
	if err := safefile.Write(path, data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func previousEnterpriseHookSuccess(dataDir, userName, userHome, connectorName string) bool {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	userName = strings.TrimSpace(userName)
	userHome = filepath.Clean(strings.TrimSpace(userHome))
	if dataDir == "" || connectorName == "" {
		return false
	}
	for _, row := range loadProtectedEnterpriseHookTargets(dataDir) {
		if !enterpriseHookRowMatches(row, userName, userHome, connectorName) {
			continue
		}
		return true
	}
	return false
}

func loadProtectedEnterpriseHookTargets(dataDir string) []enterpriseHookReconcileRow {
	path := managed.HookGuardianAuthorizationPath(dataDir)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var state enterpriseHookGuardianAuthorization
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}
	var rows []enterpriseHookReconcileRow
	for _, row := range state.ProtectedTargets {
		if row.OK {
			rows = append(rows, row)
		}
	}
	return rows
}

func mergeProtectedEnterpriseHookTargets(previous, current []enterpriseHookReconcileRow) []enterpriseHookReconcileRow {
	merged := map[string]enterpriseHookReconcileRow{}
	for _, row := range previous {
		if !row.OK {
			continue
		}
		if key := enterpriseHookProtectedTargetKey(row); key != "" {
			merged[key] = row
		}
	}
	for _, row := range current {
		if !row.OK {
			continue
		}
		if key := enterpriseHookProtectedTargetKey(row); key != "" {
			merged[key] = row
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

func enterpriseHookRowMatches(row enterpriseHookReconcileRow, userName, userHome, connectorName string) bool {
	rowConnector := strings.ToLower(strings.TrimSpace(row.Connector))
	if rowConnector == "" && row.Result != nil {
		rowConnector = strings.ToLower(strings.TrimSpace(row.Result.Connector))
	}
	if rowConnector != connectorName {
		return false
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
	if name := strings.TrimSpace(userName); name != "" {
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

func intPtrValue(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
