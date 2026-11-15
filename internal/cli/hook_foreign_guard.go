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
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
)

// standaloneForeignHookGuardBinary is the administrator-owned hook binary
// the standalone Amp and OpenCode plugins run for the foreign-hook guard
// (those plugins call the gateway directly, so the hook-time guard would
// otherwise never run for them), and on Linux and macOS the binary the
// standalone Devin hook command runs in managed mode (the per-user
// devin-hook.sh never ran the guard; Windows already registers the
// administrator-owned binary for Devin), and on Linux and macOS the binary
// the standalone hermes-hook.sh asks for the guard's decision before each
// tool call (Hermes has no managed hook source, so its per-user shell hook
// stays the registered command). Empty for every other connector and on
// any non-standalone profile, so Secure Client and per-user installs render
// unchanged.
func standaloneForeignHookGuardBinary(connectorName string) string {
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "amp", enterprisepolicy.ConnectorOpenCode:
	case "devin", enterprisepolicy.ConnectorHermes:
		if runtime.GOOS == "windows" {
			return ""
		}
	default:
		return ""
	}
	return standaloneAdminHookBinary()
}

// standaloneManagedHookBinary is the administrator-owned hook binary a
// standalone Linux or macOS connector shell hook runs as `hook
// session-facts` to read the user's Kerberos credential cache, which a
// shell cannot read and a managed user has no per-user gateway binary to
// ask (GAP-0194). Every connector gets it, not only the ones that run the
// foreign-hook guard. Empty on Windows, whose hooks are not shell scripts,
// and on any non-standalone profile, so Secure Client and per-user installs
// render unchanged.
func standaloneManagedHookBinary() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return standaloneAdminHookBinary()
}

// standaloneAdminHookBinary is the standalone profile's administrator-owned
// hook binary, or "" outside that profile.
func standaloneAdminHookBinary() string {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return ""
	}
	layout, programFiles, programData, err := hookcli.StandaloneEnterprisePolicyLayout()
	if err != nil {
		return ""
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		return ""
	}
	return opts.HookBinary
}

// perUserOwnedHookCommands lists DefenseClaw's own per-user registration
// commands for the default per-user data dir under home and any explicit
// data dir.
func perUserOwnedHookCommands(name, home, dataDir string) []string {
	return hookcli.PerUserOwnedHookCommandsForBinary(name, home, dataDir, "")
}
