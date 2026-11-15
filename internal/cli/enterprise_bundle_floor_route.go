// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// A managed Linux or macOS package before 1.0.10 has no route-only listener
// and nothing that takes back the route settings the guardian wrote into the
// Claude Code or Codex file of each enrolled account (rel-1-0-10 GAP-0568),
// so after a package downgrade every routed agent got 401 or connection
// refused (rel-1-0-10 GAP-0647). The only code of this release that runs on
// such a downgrade is floor-check: the older package preinstall (1.0.4 and
// later: rpm %pre, deb preinst, pkg preinstall) and the apt guard of this
// release run it with the installed gateway before any file is replaced.
// The rpm %preun of this release runs only after the older files are in
// place, and its deb prerm and the pkg run none of its binaries. So
// floor-check refuses a release before 1.0.10 while routing is on (the
// guardian would write the settings again), and with routing off takes back,
// as each account, any render still left before it lets the older package in.

// floorCheckInstalledConfig loads the deployed config.yaml (tests replace
// it). fs.ErrNotExist: no deployment.
var floorCheckInstalledConfig = func(env *enterpriseunix.Env) (*config.Config, error) {
	return env.InstalledConfig()
}

// floorCheckRouteBindings reads the protected target bindings of the
// guardian: the accounts it rendered for (tests replace it).
var floorCheckRouteBindings = func(env *enterpriseunix.Env) enterpriseHookUnixBindings {
	return loadEnterpriseHookUnixBindingsFile(filepath.Join(env.P(env.Layout.GuardianAuthDir), enterpriseHookUnixBindingsFile))
}

// floorCheckRouteResolver resolves the accounts of those bindings (tests
// replace it).
var floorCheckRouteResolver = enterprisehooks.StandaloneResolver

// routeOnlyDowngradeRefusal refuses installing version, a release before
// route-only, while this deployment routes an agent, or while the route
// settings of an account could not be taken back. A same or later release
// passes untouched, and so does a host whose deployment is gone: an
// uninstall (also --keep-state, which keeps config.yaml and lets the kept
// floor checker answer) removes the runtime descriptor, leaves no guardian
// to write route settings, and took them back through each connector
// teardown.
func routeOnlyDowngradeRefusal(ctx context.Context, env *enterpriseunix.Env, version string) error {
	if !rollbackTargetLacksRouteOnly(version) {
		return nil
	}
	if _, err := os.Lstat(env.P(env.Layout.DescriptorPath)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	installed, err := floorCheckInstalledConfig(env)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		// A config that exists but cannot be read may still route an agent,
		// and the guardian keeps the routing it loaded: taking the route
		// settings back now would race it writing them again (T-UPGRADE
		// review F3). Refuse, naming the file.
		return fmt.Errorf("route_only_downgrade_refused: the managed config of this deployment could not be read (%v), so DefenseClaw cannot tell whether route-only routing is on; "+
			"DefenseClaw %s has no route-only listener. Fix or restore the managed config (%s ensure --config <file>), then install the older package again",
			err, version, filepath.Join(env.Layout.BinDir, "defenseclaw-gateway")+" enterprise "+floorCheckOSName(env.GOOS))
	}
	if routed := managedRouteOnlyConnectors(installed); len(routed) > 0 {
		list := strings.Join(routed, ", ")
		return fmt.Errorf("route_only_downgrade_refused: route-only routing is on for %s, and DefenseClaw %s has no route-only listener: "+
			"every enrolled account would keep the route settings of this release and its agent would get 401 or connection refused. "+
			"Turn routing off first: remove %s from routing.route_only.connectors (or set routing.enabled: false) in the managed config "+
			"or the signed bundle and apply it (%s ensure --config <file>, or enterprise bundle apply), then install the older package again; "+
			"it takes the route settings of each account back before its files are installed",
			list, version, list, filepath.Join(env.Layout.BinDir, "defenseclaw-gateway")+" enterprise "+floorCheckOSName(env.GOOS))
	}
	// Routing is off: take back what is still rendered, as each account.
	// A restore with nothing rendered changes no file.
	if ctx == nil {
		ctx = context.Background()
	}
	left := enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}
	restoreDepartedEnterpriseHookMachineRoutes(ctx, floorCheckRouteBindings(env), left, floorCheckRouteResolver())
	if len(left.Bindings) == 0 {
		return nil
	}
	accounts := make([]string, 0, len(left.Bindings))
	for key := range left.Bindings {
		if parts := strings.SplitN(key, "\x00", 3); len(parts) == 3 {
			accounts = append(accounts, parts[2]+" "+parts[0])
		}
	}
	slices.Sort(accounts)
	return fmt.Errorf("route_only_restore_incomplete: the route-only settings of %d enrolled account(s) (%s) could not be taken back, and DefenseClaw %s does not take them back: "+
		"their agents would get 401 or connection refused. Make each account resolvable with its home available (the reason is in the lines above) "+
		"and install the older package again, or first remove the DefenseClaw base URL and route header from its ~/.claude/settings.json env "+
		"or the defenseclaw_route provider from its ~/.codex/config.toml",
		len(accounts), strings.Join(accounts, ", "), version)
}

// floorCheckOSName is the enterprise subcommand of goos.
func floorCheckOSName(goos string) string {
	if goos == "darwin" {
		return "macos"
	}
	return "linux"
}
