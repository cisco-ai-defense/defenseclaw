// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Standalone uninstall revokes every enrollment and removes the services, but
// it cannot remove the OpenCode and Amp plugins it rendered into each user's
// own profile: signed-out users have no session to act in. Those plugins
// render with DC_FAIL_MODE closed, so without a way to recognize the
// uninstall they would block every tool call afterwards. They are rendered
// with an install marker instead: the standalone hook runtime directory,
// which only the committed uninstall finalization removes, and only once
// nothing but DefenseClaw lock files remain in it. A standard user cannot
// remove it, so it grants nothing a user could not already do by deleting the
// plugin from their own profile.

// windowsStandalonePluginInstallMarker returns the install marker an in-agent
// plugin connector (OpenCode, Amp) is rendered with in a standalone process.
// Every other connector and Secure Client get none.
func windowsStandalonePluginInstallMarker(connectorName string) (string, error) {
	if !windowsStandaloneInAgentPluginConnector(connectorName) || !windowsEnterpriseStandaloneProcess() {
		return "", nil
	}
	root, err := windowsStandaloneHookRuntimeRoot()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve the standalone install marker: %w", err)
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", fmt.Errorf("enterprise hooks: refusing noncanonical standalone install marker %s", root)
	}
	return root, nil
}

// applyWindowsStandalonePluginOptions sets the options a standalone render of
// an in-agent plugin connector (OpenCode, Amp) carries: the install marker
// above, and the listener proof. Those plugins reach the gateway over
// loopback TCP and, unlike the hook binary, cannot compare the listener
// with the SCM gateway process, so they make it prove it can derive the
// user's per-user credential before sending that credential or any hook
// payload (connector.UserScopedListenerProof). OpenCode counts even though
// it is classed as a hook-binary connector for its machine policy route:
// on the per-user route it still renders the TCP plugin. Every other
// connector and Secure Client get neither.
func applyWindowsStandalonePluginOptions(connectorName string, setup *connector.SetupOpts) error {
	marker, err := windowsStandalonePluginInstallMarker(connectorName)
	if err != nil {
		return err
	}
	setup.ManagedInstallMarker = marker
	setup.ManagedListenerProof = windowsStandaloneInAgentPluginConnector(connectorName) && windowsEnterpriseStandaloneProcess()
	return nil
}

// ensureWindowsStandalonePluginInstallMarker creates the install marker, as a
// protected administrator-owned directory, before a plugin that names it is
// rendered: a plugin whose marker is missing stops failing closed.
func ensureWindowsStandalonePluginInstallMarker(marker string) error {
	if marker == "" {
		return nil
	}
	if err := ensureWindowsManagedPolicyDirectory(marker); err != nil {
		return fmt.Errorf("enterprise hooks: create the standalone install marker: %w", err)
	}
	return nil
}

// verifyWindowsStandalonePluginInstallMarker requires the install marker of a
// managed plugin to be present as a plain directory, so a deployment whose
// marker went missing is repaired instead of reported healthy.
func verifyWindowsStandalonePluginInstallMarker(marker string) error {
	if marker == "" {
		return nil
	}
	exists, err := windowsHookRuntimePlainDirectory(marker)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("enterprise hooks: standalone install marker %s is missing, so managed plugins would not fail closed", marker)
	}
	return nil
}
