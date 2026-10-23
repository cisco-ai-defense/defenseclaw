// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var connectorRefreshFailModesCmd = &cobra.Command{
	Use:   "refresh-fail-modes",
	Short: "Set the installed hooks' outage fail modes from the config (run by the installers)",
	Long: `Set the fail mode every installed per-user hook follows while the gateway
is down from config.yaml, without touching agent configuration or restarting
anything. hooks/.hookcfg and its flat records get the mode the config chooses,
and a connector hook script that bakes an open the config does not choose is
closed until the gateway renders it. The installers run it with the new
release's gateway. With --hold-until-exit PID (the running gateway) it
holds the lock every release's hook writer takes after the first refresh,
prints "Holding the hook fail modes", and refreshes again once that gateway
has exited, before it lets go: the old gateway cannot render its open again
while it stops. So no hook follows an open an earlier release recorded for a
mode nobody set. While an installer holds the data directory (.install.lock)
every hook is closed, an open the config sets included: the hooks of an
earlier release do not check that lock, and no hook may let a call run
during an install or upgrade. The gateway renders the config's modes when
it starts. Otherwise an open the config sets stays open. A config this
release cannot load yet (a 0.8.x one before 'defenseclaw migrate') is read
for its explicit fail modes only. Managed installs are not changed.`,
	Hidden: true,
	// It runs beside the gateway it is about to replace: RunE loads the
	// config only (and still reads one it cannot load), never a second audit
	// store.
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
	Annotations:       map[string]string{auditOptionalAnnotation: "true"},
	RunE:              runConnectorRefreshFailModes,
}

// hookFailModeHoldMarker is the line the installers wait for: the lock is
// held and the first refresh is written.
const hookFailModeHoldMarker = "Holding the hook fail modes"

var (
	refreshFailModesHoldPID     int
	refreshFailModesHoldTimeout time.Duration
)

func init() {
	connectorRefreshFailModesCmd.Flags().IntVar(&refreshFailModesHoldPID, "hold-until-exit", 0,
		"hold the hook fail modes until the gateway with this process ID exits, then refresh them again")
	connectorRefreshFailModesCmd.Flags().DurationVar(&refreshFailModesHoldTimeout, "hold-timeout", 2*time.Minute,
		"longest wait for that gateway to exit")
	connectorCmd.AddCommand(connectorRefreshFailModesCmd)
}

// refreshFailModesProcessRunning reports whether the gateway being stopped
// is still running (watchdogChildRunning: signal 0, or an open process
// handle on Windows).
var refreshFailModesProcessRunning = watchdogChildRunning

func runConnectorRefreshFailModes(cmd *cobra.Command, _ []string) error {
	mode, read, managedInstall := refreshFailModeResolver(cmd)
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		dataDir = config.DefaultDataPath()
	}
	if !managedInstall && refreshFailModesInstallHeld(dataDir) {
		// The installers run this while they hold the data directory. The
		// hooks of 0.8.10 to 1.0.3 never read that lock, so an open they
		// follow lets a call run while the gateway is down for the swap
		// (GAP-1001): every hook is closed for the install, and the new
		// gateway renders the config's modes when it starts.
		mode = func(string) string { return "closed" }
		read = "install"
	}
	hookDir := filepath.Join(dataDir, "hooks")
	if refreshFailModesHoldPID != 0 {
		if connectorFlagJSON {
			return errors.New("connector refresh-fail-modes: --hold-until-exit does not take --json")
		}
		if refreshFailModesHoldPID < 0 || refreshFailModesHoldTimeout <= 0 {
			return errors.New("connector refresh-fail-modes: --hold-until-exit takes a process ID and --hold-timeout a positive time")
		}
		return holdConnectorFailModes(cmd, hookDir, mode, read, managedInstall)
	}
	var result connector.HookFailModeRefresh
	if !managedInstall {
		var err error
		result, err = connector.RefreshHookFailModes(hookDir, mode)
		if err != nil {
			return fmt.Errorf("connector refresh-fail-modes: %w", err)
		}
	}
	if connectorFlagJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"action": "refresh-fail-modes", "ok": true, "config": read,
			"refreshed": nonNilStrings(result.Sidecar), "scripts": nonNilStrings(result.Scripts),
		})
	}
	printHookFailModeRefresh(cmd, result, read)
	if len(result.Scripts) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Hooks closed until the gateway starts: %s\n", strings.Join(result.Scripts, ", "))
	}
	return nil
}

// holdConnectorFailModes is refresh-fail-modes --hold-until-exit: the
// refresh under the sidecar lock held until the gateway exits
// (connector.HoldHookFailModes). A managed install is left alone and has
// nothing to hold.
func holdConnectorFailModes(cmd *cobra.Command, hookDir string, mode func(string) string, read string, managedInstall bool) error {
	out := cmd.OutOrStdout()
	held := func(first connector.HookFailModeRefresh) {
		printHookFailModeRefresh(cmd, first, read)
		fmt.Fprintf(out, "%s until the gateway (process %d) exits\n", hookFailModeHoldMarker, refreshFailModesHoldPID)
	}
	if managedInstall {
		held(connector.HookFailModeRefresh{})
		return nil
	}
	pid := refreshFailModesHoldPID
	result, err := connector.HoldHookFailModes(hookDir, mode, held,
		func() bool { return refreshFailModesProcessRunning(pid) }, refreshFailModesHoldTimeout)
	if err != nil {
		return fmt.Errorf("connector refresh-fail-modes: %w", err)
	}
	if len(result.Scripts) > 0 {
		fmt.Fprintf(out, "Hooks closed until the gateway starts: %s\n", strings.Join(result.Scripts, ", "))
	}
	return nil
}

func printHookFailModeRefresh(cmd *cobra.Command, result connector.HookFailModeRefresh, read string) {
	if len(result.Sidecar) == 0 {
		return
	}
	if read == "install" {
		fmt.Fprintf(cmd.OutOrStdout(), "Hook fail modes closed for the install until the gateway starts: %s\n", strings.Join(result.Sidecar, ", "))
		return
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Hook fail modes set from the config: %s\n", strings.Join(result.Sidecar, ", "))
}

// refreshFailModesInstallHeld reports whether an installer holds the data
// directory the refresh writes, or the one DEFENSECLAW_HOME names (where
// install.sh and install.ps1 take the lock): hookexec.InstallLockHeld, as the
// hooks of this release read it.
func refreshFailModesInstallHeld(dataDir string) bool {
	return hookexec.InstallLockHeld(dataDir) || hookexec.InstallLockHeld(config.DefaultDataPath())
}

// refreshFailModeResolver returns the outage fail mode the config chooses for
// each connector (connector.OutageHookFailMode: open only where the config
// sets it), how the config was read ("loaded" or "document"; the refresh
// reports "install" when an installer holds the data directory), and whether
// the install is managed, which is left alone.
func refreshFailModeResolver(cmd *cobra.Command) (func(string) string, string, bool) {
	if err := loadGatewayCommandConfigFor(cmd); err == nil && cfg != nil {
		if managed.IsManagedEnterprise(cfg.DeploymentMode) {
			return nil, "loaded", true
		}
		loaded := cfg
		reg := newConnectorRegistryWithPlugins()
		return func(name string) string {
			var conn connector.Connector
			if found, ok := reg.Get(name); ok && name != "" {
				conn = found
			}
			return connector.OutageHookFailMode(connector.SetupOpts{
				HookFailMode:             loaded.EffectiveHookFailModeForConnector(name),
				ConfiguredHookFailMode:   loaded.ConfiguredHookFailModeForConnector(name),
				SecureClientHookDelivery: loaded.SecureClientIntegration(),
				GuardrailMode:            loaded.EffectiveGuardrailModeForConnector(name),
			}, conn)
		}, "loaded", false
	}
	// This release cannot load the config: a 0.8.x one before 'defenseclaw
	// migrate', which the installer's 'migrate --check' has just validated,
	// or none. Its explicit fail modes are the operator's (every migration
	// keeps them); everything else is closed, Cursor included.
	raw := readHookConfigDocument(config.ConfigPath())
	if config.ManagedEnterpriseDocument(raw) {
		return nil, "document", true
	}
	return func(name string) string {
		if config.ConfiguredHookFailModeInDocument(raw, name) == "open" {
			return "open"
		}
		return "closed"
	}, "document", false
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
