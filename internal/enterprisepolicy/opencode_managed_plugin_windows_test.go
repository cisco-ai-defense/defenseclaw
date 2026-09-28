// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The Windows guardian installs the managed OpenCode plugin the payload
// carries under Program Files before it publishes OpenCode's managed
// config, so OpenCode takes the machine-policy route; teardown removes the
// entry and then the plugin.
func TestPublishWindowsGoOwnedInstallsTheOpenCodePlugin(t *testing.T) {
	opts := windowsOpenCodeTestOptions(t)
	if route := opts.Route(ConnectorOpenCode); route != RoutePerUser {
		t.Fatalf("before the guardian installs the plugin OpenCode is per-user, got %s", route)
	}

	result, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(opts.OpenCodePluginPath)
	if err != nil || string(data) != string(OpenCodeManagedPlugin()) {
		t.Fatalf("the guardian must install the shipped plugin: %v", err)
	}
	if err := validateTrustedFile(opts.OpenCodePluginPath); err != nil {
		t.Fatalf("the installed plugin must pass the machine trust rules: %v", err)
	}
	for _, dir := range []string{filepath.Dir(opts.OpenCodePluginPath), filepath.Dir(filepath.Dir(opts.OpenCodePluginPath))} {
		requireProtected(t, dir)
	}
	if len(result.MachinePolicyConnectors) != 1 || result.MachinePolicyConnectors[0] != ConnectorOpenCode {
		t.Fatalf("OpenCode must be published through machine policy: %+v", result)
	}
	config, _ := OpenCodeManagedConfigPath(opts)
	if body, err := os.ReadFile(config); err != nil || !strings.Contains(string(body), strings.ReplaceAll(opts.OpenCodePluginPath, `\`, `\\`)) {
		t.Fatalf("OpenCode's managed config must name the plugin: %v\n%s", err, body)
	}
	again, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode})
	if err != nil || again.Changed {
		t.Fatalf("a second publish must be a no-op: changed=%v err=%v", again.Changed, err)
	}
	if err := os.WriteFile(opts.OpenCodePluginPath, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if repaired, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode}); err != nil || !repaired.Changed {
		t.Fatalf("publish must repair a stale plugin: changed=%v err=%v", repaired.Changed, err)
	}

	if _, err := RemoveWindowsGoOwned(opts); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{opts.OpenCodePluginPath, filepath.Dir(opts.OpenCodePluginPath), filepath.Dir(filepath.Dir(opts.OpenCodePluginPath))} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s must be removed: %v", gone, err)
		}
	}
	if body, err := os.ReadFile(config); err == nil && strings.Contains(string(body), "defenseclaw.js") {
		t.Fatalf("teardown must remove DefenseClaw's OpenCode entry:\n%s", body)
	}
}

// windowsOpenCodeTestOptions are Windows test options with a protected
// Program Files install root that carries the managed OpenCode plugin path.
func windowsOpenCodeTestOptions(t *testing.T) Options {
	t.Helper()
	opts := windowsTestOptions(t)
	root := filepath.Dir(opts.WindowsProgramData)
	programFiles := filepath.Join(root, "Program Files")
	if err := createProtectedDir(programFiles); err != nil {
		t.Fatal(err)
	}
	testWindowsTrust(t, root)
	install := filepath.Join(programFiles, "Cisco", "DefenseClaw")
	opts.WindowsProgramFiles = programFiles
	opts.HookBinary = filepath.Join(install, "bin", "defenseclaw-hook.exe")
	opts.OpenCodePluginPath = filepath.Join(install, "share", "opencode", "defenseclaw.js")
	return opts
}

// The guardian installs the managed plugin on every pass, before it
// reconciles OpenCode's managed config. With ownership: off that config never
// names the plugin, so the summary the per-user plugin's guard reads must
// keep OpenCode per-user (a machine-policy summary would deny every OpenCode
// tool call on DefenseClaw's own per-user plugin). Once the config names the
// plugin the summary moves OpenCode onto machine policy.
func TestPublishWindowsGoOwnedKeepsTheOpenCodeSummaryPerUserWithOwnershipOff(t *testing.T) {
	merge := windowsOpenCodeTestOptions(t)
	merge.PublicPolicyPath = filepath.Join(merge.WindowsProgramData, "machine-policy.json")
	off := withPolicy(merge, ConnectorOpenCode, func(p *config.EnterpriseConnectorPolicy) {
		p.Ownership = config.MachinePolicyOwnershipOff
	})
	summaryRoute := func() string {
		t.Helper()
		data, err := os.ReadFile(merge.PublicPolicyPath)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParsePublicPolicy(data)
		if err != nil {
			t.Fatal(err)
		}
		return parsed.Connectors[ConnectorOpenCode].Route
	}

	result, err := PublishWindowsGoOwned(off, []string{ConnectorOpenCode})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(off.OpenCodePluginPath); err != nil {
		t.Fatalf("the guardian still installs the shipped plugin: %v", err)
	}
	if len(result.MachinePolicyConnectors) != 0 {
		t.Fatalf("ownership off must not publish OpenCode: %+v", result)
	}
	if route := summaryRoute(); route != RoutePerUser {
		t.Fatalf("with ownership off the summary must keep OpenCode per-user, got %s", route)
	}

	if _, err := PublishWindowsGoOwned(merge, []string{ConnectorOpenCode}); err != nil {
		t.Fatal(err)
	}
	if route := summaryRoute(); route != RouteMachinePolicy {
		t.Fatalf("once the managed config names the plugin the summary must report machine policy, got %s", route)
	}
}
