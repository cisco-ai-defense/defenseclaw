// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// hookOutageFailModeNow is the gateway-outage mode the config of the per-user
// hook runtime in hookDir gives connectorName's hooks now
// (config.HookOutageFailMode of its policy tier): "open" only when this
// release loads that config, the install is neither managed nor Secure
// Client, and the connector's rule pack is not strict. Every other case is
// "closed".
//
// A per-user hook asks only for a classified gateway outage. Its current
// config decides even when a setup-time record has a different tier.
//
// The policy source is the runtime's own config, config.yaml in the data
// directory above hookDir, whose data_dir is that directory: the folder the
// gateway rendered the hooks into. The hook process's DEFENSECLAW_CONFIG and
// DEFENSECLAW_HOME come from the agent and never choose it or its data
// directory (loadHookRuntimeConfig), so an agent that points them at another
// default-tier config cannot reopen a strict outage. A config kept outside
// its data directory closes the outage, except the account's own config when
// the data directory holds none (hookRuntimeConfigPath): `defenseclaw config
// set data_dir` moves the hooks and leaves config.yaml in the account's home.
//
// An install or upgrade of this account's DefenseClaw is not an outage
// either: while any folder an installer of this account may hold carries its
// .install.lock, the answer is "closed" (hookOutageInstallHeld).
func hookOutageFailModeNow(connectorName, hookDir string) string {
	return hookOutageFailModeFor(connectorName, hookDir, false)
}

// hookOutageFailModeFor is hookOutageFailModeNow; installWindow leaves out
// the install-lock check only (hookOutageInstallHeld). It is the mode an
// install window gives a call this account's gateway answered: "open" (the
// default and permissive tiers, or a saved open) lets that answer through
// with a warning, "closed" (the strict tier, a saved closed, a managed or
// Secure Client install, any doubt) blocks it.
func hookOutageFailModeFor(connectorName, hookDir string, installWindow bool) string {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	hookDir = strings.TrimSpace(hookDir)
	if name == "" || hookDir == "" || !filepath.IsAbs(hookDir) {
		return "closed"
	}
	dataDir := filepath.Dir(filepath.Clean(hookDir))
	configFile := hookRuntimeConfigPath(dataDir)
	loaded, ownDataDir, err := loadHookRuntimeConfig(configFile)
	if err != nil || loaded == nil || managed.IsManagedEnterprise(loaded.DeploymentMode) || loaded.SecureClientIntegration() {
		return "closed"
	}
	// The machine installation marker is an independent managed signal. A
	// leftover per-user hook cannot reopen a managed host just because its
	// own config still says OSS; an unreadable marker state also closes it.
	if secureClientHost() {
		return "closed"
	}
	if _, present := managedHostWindowsStandalone(); present {
		return "closed"
	}
	// A Windows machine marker that exists but cannot be verified, or whose
	// registry key cannot be read, is not proof of an OSS host. Only a
	// definite absence may leave the per-user outage open.
	if managedHostWindowsMarkerUncertain() {
		return "closed"
	}
	if marker := managedHostDescriptorPath(); marker != "" {
		if _, err := os.Lstat(marker); err == nil || !errors.Is(err, os.ErrNotExist) {
			return "closed"
		}
	}
	// A config whose data_dir is elsewhere is not this runtime's config,
	// except the account's config after a data_dir move: hooks left behind
	// follow the moved folder's answer (movedDataDirOutageMode).
	// The data directory is the one hook-data-dir names for install.sh to
	// lock (loadHookRuntimeConfig): a relative data_dir is taken from the
	// config's folder, never from the agent's working directory.
	if ownDataDir == "" || !pathidentity.Same(ownDataDir, dataDir) {
		return movedDataDirOutageMode(name, dataDir, configFile, ownDataDir, installWindow)
	}
	if !installWindow && hookOutageInstallHeld(dataDir) {
		return "closed"
	}
	if loaded.EffectiveHookOutageFailModeForConnector(name) == "open" {
		return "open"
	}
	return "closed"
}

// movedDataDirOutageMode is the outage mode of hooks left in a data
// directory that `defenseclaw config set data_dir` moved away from: the
// config they load names ownDataDir (rel-1-0-6 GAP-0224, sweep 8). The
// gateway renders the hooks into the new <data_dir>/hooks, but an agent
// session started before the move keeps running the hooks it loaded at its
// start: Claude Code keeps a snapshot of its hook commands for the session
// (/clear does not reload it), Codex and OpenCode read theirs once. Before
// this, such a session failed closed on every outage while a new session
// failed open.
//
// Two folders qualify, both running under the account's own config, the
// one the moved folder's hooks read too (hookRuntimeConfigPath): the
// account's .defenseclaw (named by the account database only, never HOME or
// DEFENSECLAW_HOME), and a folder with no config.yaml of its own, whose
// hooks load the account's config (a move back from a custom data_dir).
// They get the answer the hooks of ownDataDir get now, with every check it
// makes (strict, a saved closed, an install lock, a config.yaml of the new
// folder), and an install lock in their own folder closes too. A folder with
// a config.yaml of its own that keeps its data elsewhere stays closed.
func movedDataDirOutageMode(name, dataDir, configFile, ownDataDir string, installWindow bool) string {
	home := outageAccountHome()
	if home == "" || ownDataDir == "" || !filepath.IsAbs(ownDataDir) {
		return "closed"
	}
	accountData := filepath.Join(home, config.DefaultDataDirName)
	accountConfig := filepath.Join(accountData, config.DefaultConfigName)
	switch {
	case pathidentity.Same(dataDir, accountData):
	case !pathidentity.Same(configFile, filepath.Join(dataDir, config.DefaultConfigName)) &&
		pathidentity.Same(configFile, accountConfig):
	default:
		return "closed"
	}
	if !installWindow && hookOutageInstallHeld(dataDir) {
		return "closed"
	}
	// The new folder's config (its own config.yaml, or the account's when it
	// has none) must name ownDataDir as its data directory, so the answer
	// below takes one step and never comes back here.
	_, movedOwn, err := loadHookRuntimeConfig(hookRuntimeConfigPath(ownDataDir))
	if err != nil || movedOwn == "" || !pathidentity.Same(movedOwn, ownDataDir) {
		return "closed"
	}
	return hookOutageFailModeFor(name, filepath.Join(ownDataDir, "hooks"), installWindow)
}

// hookRuntimeConfigPath is the config file of the per-user hook runtime
// whose data directory is dataDir: config.yaml in dataDir, or, when dataDir
// has none, the account's own config, found from the account database
// (outageAccountHome, and on Windows the installed runtime's protected data
// root first), never from HOME, USERPROFILE, DEFENSECLAW_HOME or
// DEFENSECLAW_CONFIG. A custom data_dir (`defenseclaw config set data_dir`)
// keeps config.yaml in ~/.defenseclaw while the gateway renders the hooks
// into <data_dir>/hooks, so that config is the one those hooks run under.
// hookOutageFailModeFor still opens an outage only when the config's data_dir
// is dataDir; before this a custom data_dir closed every outage (rel-1-0-6
// GAP-0224). A config.yaml in dataDir that exists in any form, or cannot be
// shown absent, stays the answer, so a broken one still closes.
func hookRuntimeConfigPath(dataDir string) string {
	own := filepath.Join(dataDir, config.DefaultConfigName)
	if _, err := os.Lstat(own); !errors.Is(err, fs.ErrNotExist) {
		return own
	}
	var roots []string
	if root, recognized := outageInstalledDataRoot(); recognized && filepath.IsAbs(root) {
		roots = append(roots, root)
	}
	if home := outageAccountHome(); home != "" {
		roots = append(roots, filepath.Join(home, config.DefaultDataDirName))
	}
	for _, root := range roots {
		candidate := filepath.Join(filepath.Clean(root), config.DefaultConfigName)
		if _, err := os.Lstat(candidate); err == nil {
			return candidate
		}
	}
	return own
}

// hookOutageInstallHeld reports whether an installer may hold this
// account's DefenseClaw while the hook runtime in dataDir asks to let an
// outage through. The installer stops the gateway and starts it again when
// it is done; that window is never an outage. It is held when the
// .install.lock of any folder below exists, as any file type, and is not
// stale (its installer is proven gone), or one of
// those folders exists but is not a folder that can be searched, so the lock
// cannot be shown absent (hookexec.InstallLockHeld):
//
//   - dataDir, the runtime's own data directory. install.sh holds a data_dir
//     set apart from DEFENSECLAW_HOME as well (hold_hook_data_dir).
//   - This account's .defenseclaw from the account database (getpwuid on
//     Linux and macOS, the Profile known folder on Windows), the installer's
//     default DEFENSECLAW_HOME. HOME and USERPROFILE never choose it.
//   - On Windows, the data root of the installed runtime's protected install
//     state, install.ps1's DEFENSECLAW_HOME. A recognized state that cannot
//     be read counts as held.
//   - The hook process's DEFENSECLAW_HOME, and .defenseclaw in its HOME (and
//     USERPROFILE on Windows), which a hook started by an agent inherits.
//
// The environment can only add a folder to look in. It never replaces one
// of the others, so an agent that runs the hook with a temporary HOME or
// another DEFENSECLAW_HOME cannot hide the installer's lock; it can only
// close an outage. Relative values name no installer folder and are skipped.
func hookOutageInstallHeld(dataDir string) bool {
	roots := []string{dataDir}
	if home := outageAccountHome(); home != "" {
		roots = append(roots, filepath.Join(home, config.DefaultDataDirName))
	}
	if root, recognized := outageInstalledDataRoot(); recognized {
		if !filepath.IsAbs(root) {
			return true
		}
		roots = append(roots, root)
	}
	if home := os.Getenv("DEFENSECLAW_HOME"); filepath.IsAbs(home) {
		roots = append(roots, home)
	}
	for _, name := range outageHomeEnvNames {
		if home := os.Getenv(name); filepath.IsAbs(home) {
			roots = append(roots, filepath.Join(home, config.DefaultDataDirName))
		}
	}
	for _, root := range roots {
		if outageInstallLockHeld(root) {
			return true
		}
	}
	return false
}

// outageInstallLockHeld reports whether the installer may hold root:
// root/.install.lock exists, as any file type, or cannot be shown absent,
// or root exists but is not a folder (Windows reports a child of a file as
// absent). A root that does not exist holds no lock; a link to a folder is
// read as that folder.
func outageInstallLockHeld(root string) bool {
	if hookexec.InstallLockHeld(root) {
		return true
	}
	info, err := os.Stat(root)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	return !info.IsDir()
}

func init() {
	var connectorName, hookDir string
	var installWindow bool
	cmd := &cobra.Command{
		Use:    "hook-outage-mode",
		Short:  "Print the gateway-outage mode the config gives a per-user connector's hooks now",
		Hidden: true,
		// A hook runs it while the gateway is down: no daemon bootstrap,
		// no audit store, only a read of config.yaml.
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), hookOutageFailModeFor(connectorName, hookDir, installWindow))
			return err
		},
	}
	cmd.Flags().StringVar(&connectorName, "connector", "", "connector name")
	cmd.Flags().StringVar(&hookDir, "hook-dir", "", "absolute hooks folder of the hook runtime asking")
	cmd.Flags().BoolVar(&installWindow, "install-window", false, "print the mode for a call the gateway answered while an installer holds the data directory")
	_ = cmd.MarkFlagRequired("connector")
	rootCmd.AddCommand(cmd)
}
