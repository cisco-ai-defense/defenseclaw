//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// Managed Windows route-only rendering (S1 DESIGN 17.7, 18.3, 21): the
// guardian writes the route-only keys only into the enrolled target own
// agent file (Claude Code settings.json env, the Codex config.toml route
// provider) with that target own route credential and the custody
// placeholder (16.2), never into managed-settings.json, the Codex
// requirements or any other machine-wide file. Every write runs as the
// target (impersonated), so no LocalSystem write lands in a user-writable
// folder. InstallOptions.RouteOnly nil removes an earlier render.

// windowsRouteOnlyWarn receives best-effort notes; replaceable in tests.
var windowsRouteOnlyWarn = func(message string) {
	fmt.Fprintf(os.Stderr, "[enterprise-hooks] WARN %s\n", message)
}

// applyWindowsRouteOnly writes (route != nil) or removes (nil) the
// route-only keys of conn; the record of the replaced values lives in the
// per-user data dir. The caller runs it as the target with the connector
// home override on the target profile.
func applyWindowsRouteOnly(conn connector.Connector, dataDir string, route *connector.RouteOnlySetup) error {
	routed, ok := conn.(connector.RouteOnlyConnector)
	if !ok {
		return nil
	}
	setup := connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: true, RouteOnly: route}
	if err := routed.ApplyRouteOnly(setup, route); err != nil {
		return fmt.Errorf("enterprise hooks: %s route-only settings: %w", conn.Name(), err)
	}
	return nil
}

// restoreWindowsRouteOnlyAsTarget takes a render back as the target: after
// a failed install (the target is not protected, so its route credential
// is refused and its agent would only get 401) and when the target leaves.
func restoreWindowsRouteOnlyAsTarget(conn connector.Connector, sid *windows.SID, home, dataDir string) error {
	return windowsEnterpriseTargetImpersonation(sid, home, func() error {
		return connector.WithUserHomeDir(home, func() error {
			return applyWindowsRouteOnly(conn, dataDir, nil)
		})
	})
}

// verifyWindowsRouteOnly fails with route_config_drift when the rendering
// differs from the one config.yaml selects (edited, missing, stale
// credential, or left after routing was turned off), so the guardian
// repair re-renders it. Read only. Verify runs as the service and these
// files are the target own, so they are read as the other account checks
// read them (readWindowsAccountConfig: bounded, a link only to a file the
// account owns, a share or mapped drive as the account; S1
// REVIEW-code-winroute P3-3), with errors that carry no path or content.
func verifyWindowsRouteOnly(conn connector.Connector, sid *windows.SID, home, dataDir string, route *connector.RouteOnlySetup) error {
	read := func(path string) ([]byte, error) {
		data, _, err := readWindowsAccountConfig(path, sid, home)
		return data, windowsRouteOnlyReadError(err)
	}
	return connector.WithUserHomeDir(home, func() error {
		if err := connector.RouteOnlyDriftWithReader(conn, connector.SetupOpts{DataDir: dataDir}, route, read); err != nil {
			return fmt.Errorf("enterprise hooks: %w", err)
		}
		return nil
	})
}

// windowsRouteOnlyReadError is the category of a failed account-file read:
// os.ErrNotExist kept, never the path or the underlying text.
func windowsRouteOnlyReadError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		return os.ErrNotExist
	case errors.Is(err, errWindowsAccountFileNotOwned):
		return errors.New("an agent file is reached through a link to a file the account does not own")
	case errors.Is(err, errWindowsAccountConfigNeedsSession):
		return errors.New("an agent file is read as the account and the account has no signed-in session")
	case errors.Is(err, connector.ErrUserNativeOTLPFileTooLarge):
		return errors.New("an agent file is larger than the read limit")
	}
	return errors.New("an agent file cannot be read")
}

// restoreWindowsRouteOnlyAfterRemoval runs the route-only restore of a
// removed target, called only once the removal succeeded, and only when the
// caller passes the mutation identity check: a removal that failed or was
// refused leaves the render of a target that is still enrolled and protected
// (S1 REVIEW-code-winroute P3-4).
func restoreWindowsRouteOnlyAfterRemoval(opts InstallOptions) {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		windowsRouteOnlyWarn(fmt.Sprintf("enterprise hooks: %s route-only settings were not restored for the removed target: %v", strings.ToLower(strings.TrimSpace(opts.ConnectorName)), err))
		return
	}
	removeWindowsRouteOnlyOnUnenroll(opts)
}

// removeWindowsRouteOnlyOnUnenroll restores the agent values a route-only
// render replaced when a Claude Code or Codex target is removed (DESIGN
// 7.5). Best effort: a failure is reported and never blocks the removal.
func removeWindowsRouteOnlyOnUnenroll(opts InstallOptions) {
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if (name != "claudecode" && name != "codex") || strings.TrimSpace(opts.UserHome) == "" {
		return
	}
	registry := opts.Registry
	if registry == nil {
		registry = newWindowsEnterpriseConnectorRegistry()
	}
	conn, ok := registry.Get(name)
	if !ok {
		return
	}
	home, sid, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err == nil {
		var dataDir string
		if dataDir, err = resolveWindowsEnterpriseDataDir(home, opts.DataDir); err == nil {
			err = restoreWindowsRouteOnlyAsTarget(conn, sid, home, dataDir)
		}
	}
	if err != nil {
		windowsRouteOnlyWarn(fmt.Sprintf("enterprise hooks: %s route-only settings were not restored for the removed target: %v", name, err))
	}
}
