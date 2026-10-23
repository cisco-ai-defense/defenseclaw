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
mode nobody set. An open the config sets stays open. A config this release cannot
load yet (a 0.8.x one before 'defenseclaw migrate') is read for its explicit
fail modes only. With --closed every hook is closed instead, whatever the
config chooses, until the gateway renders them again: install.ps1 runs it
when it stops with its install unfinished (a restore a running hook refused),
so no hook follows an outage open while its programs and data do not match.
Managed installs are not changed.`,
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
	refreshFailModesClosed      bool
)

func init() {
	connectorRefreshFailModesCmd.Flags().IntVar(&refreshFailModesHoldPID, "hold-until-exit", 0,
		"hold the hook fail modes until the gateway with this process ID exits, then refresh them again")
	connectorRefreshFailModesCmd.Flags().DurationVar(&refreshFailModesHoldTimeout, "hold-timeout", 2*time.Minute,
		"longest wait for that gateway to exit")
	connectorRefreshFailModesCmd.Flags().BoolVar(&refreshFailModesClosed, "closed", false,
		"close every installed hook, whatever the config chooses, until the gateway renders them again")
	connectorCmd.AddCommand(connectorRefreshFailModesCmd)
}

// refreshFailModesProcessRunning reports whether the gateway being stopped
// is still running (watchdogChildRunning: signal 0, or an open process
// handle on Windows).
var refreshFailModesProcessRunning = watchdogChildRunning

func runConnectorRefreshFailModes(cmd *cobra.Command, _ []string) error {
	mode, read, managedInstall := refreshFailModeResolver(cmd)
	if refreshFailModesClosed {
		mode = func(string) string { return "closed" }
	}
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		dataDir = config.DefaultDataPath()
	}
	hookDir := filepath.Join(dataDir, "hooks")
	if refreshFailModesHoldPID != 0 {
		if connectorFlagJSON {
			return errors.New("connector refresh-fail-modes: --hold-until-exit does not take --json")
		}
		if refreshFailModesClosed {
			return errors.New("connector refresh-fail-modes: --closed does not take --hold-until-exit")
		}
		if refreshFailModesHoldPID < 0 || refreshFailModesHoldTimeout <= 0 {
			return errors.New("connector refresh-fail-modes: --hold-until-exit takes a process ID and --hold-timeout a positive time")
		}
		return holdConnectorFailModes(cmd, hookDir, mode, managedInstall)
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
	printHookFailModeRefresh(cmd, result)
	if len(result.Scripts) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Hooks closed until the gateway starts: %s\n", strings.Join(result.Scripts, ", "))
	}
	return nil
}

// holdConnectorFailModes is refresh-fail-modes --hold-until-exit: the
// refresh under the sidecar lock held until the gateway exits
// (connector.HoldHookFailModes). A managed install is left alone and has
// nothing to hold.
func holdConnectorFailModes(cmd *cobra.Command, hookDir string, mode func(string) string, managedInstall bool) error {
	out := cmd.OutOrStdout()
	held := func(first connector.HookFailModeRefresh) {
		printHookFailModeRefresh(cmd, first)
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

func printHookFailModeRefresh(cmd *cobra.Command, result connector.HookFailModeRefresh) {
	if len(result.Sidecar) == 0 {
		return
	}
	if refreshFailModesClosed {
		fmt.Fprintf(cmd.OutOrStdout(), "Hooks closed until the gateway renders them: %s\n", strings.Join(result.Sidecar, ", "))
		return
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Hook fail modes set from the config: %s\n", strings.Join(result.Sidecar, ", "))
}

// refreshFailModeResolver returns the outage fail mode the config chooses for
// each connector (connector.OutageHookFailMode: open only where the config
// sets it), how the config was read ("loaded" or "document"), and whether
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
