// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

// The connectors block counts plain rows: enabled-only, detected without a
// version, a version that is not a token, unattested guardian state, mixed
// protected and failed targets, machine and per-user hooks, and a fail mode
// that is whatever the resolver returns.
func TestBuildConnectorsCountsRowsWithoutAccounts(t *testing.T) {
	resolver := map[string]string{"codex": "closed", "amp": "open", "hermes": "open"}
	failMode := func(name string) string { return resolver[name] }
	mode := func(name string) string {
		if name == "codex" {
			return "action"
		}
		return "observe"
	}
	in := ConnectorInputs{
		ConfigLoaded: true, Enabled: []string{"codex", "amp", "hermes", "Bogus Name"}, Mode: mode,
		ManifestRead: true,
		Manifest: []ConnectorInstall{
			{Connector: "codex", Version: "0.160.0", Enabled: true},
			{Connector: "codex", Version: "0.161.0", Enabled: true},
			{Connector: "codex", Version: "0.160.0", Enabled: true},
			{Connector: "amp", Enabled: true},
			{Connector: "cursor", Version: "2026.10.01", Enabled: true},
		},
		Unprotected:   []ConnectorInstall{{Connector: "codex", Version: "1.0 beta; rm -rf"}},
		GuardianKnown: true,
		Guardian: []ConnectorTarget{
			{Connector: "codex", OK: true}, {Connector: "codex", OK: true}, {Connector: "codex"},
			{Connector: "amp", Pending: true}, {Connector: "cursor", OK: true},
		},
		MachinePolicy: []string{"codex"},
	}
	block, hidden := BuildConnectors(in, failMode)
	if hidden != 1 {
		t.Fatalf("hidden = %d, want the one non-token version", hidden)
	}
	want := map[string]ConnectorState{
		"codex": {Enabled: true, Detected: boolPtr(true), Versions: []string{"0.160.0", "0.161.0"}, HooksInstalled: HooksInstalledPartial,
			Targets: &ConnectorTargets{Total: 3, Protected: 2, Failed: 1}, EffectiveMode: "action", EffectiveHookFailMode: "closed", ManagedHook: boolPtr(true)},
		"amp": {Enabled: true, Detected: boolPtr(true), HooksInstalled: HooksInstalledNone,
			Targets: &ConnectorTargets{Total: 1, Pending: 1}, EffectiveMode: "observe", EffectiveHookFailMode: "open", ManagedHook: boolPtr(false)},
		"hermes": {Enabled: true, Detected: boolPtr(false), HooksInstalled: HooksInstalledNone,
			Targets: &ConnectorTargets{}, EffectiveMode: "observe", EffectiveHookFailMode: "open", ManagedHook: boolPtr(false)},
		// Disabled while its targets remain: listed, no detected or managed_hook.
		"cursor": {Versions: []string{"2026.10.01"}, HooksInstalled: HooksInstalledAll,
			Targets: &ConnectorTargets{Total: 1, Protected: 1}, EffectiveMode: "observe"},
	}
	if !reflect.DeepEqual(block, want) {
		got, _ := json.MarshalIndent(block, "", " ")
		t.Fatalf("block:\n%s", got)
	}
}

// The reported fail mode is the resolver's answer for every connector and
// mode, never a constant: when the resolver changes (fix/r103-B20 makes
// every managed standalone hook closed) the block follows it.
func TestBuildConnectorsReportsTheResolverFailMode(t *testing.T) {
	for _, answer := range []string{"open", "closed", "OPEN", "something-else"} {
		in := ConnectorInputs{ConfigLoaded: true, Enabled: []string{"amp", "kiro", "antigravity", "hermes", "codex"}}
		block, _ := BuildConnectors(in, func(string) string { return answer })
		for name, state := range block {
			want := strings.ToLower(answer)
			if want != "open" && want != "closed" {
				want = ""
			}
			if state.EffectiveHookFailMode != want {
				t.Fatalf("%s: effective_hook_fail_mode %q, resolver %q", name, state.EffectiveHookFailMode, answer)
			}
		}
	}
}

func TestBuildConnectorsWithoutConfigOrState(t *testing.T) {
	in := ConnectorInputs{ManifestRead: true, Manifest: []ConnectorInstall{
		{Connector: "codex", Enabled: true}, {Connector: "amp", Enabled: false},
	}, Known: func(name string) bool { return name != "unknownagent" }}
	in.Manifest = append(in.Manifest, ConnectorInstall{Connector: "unknownagent", Enabled: true})
	block, _ := BuildConnectors(in, func(string) string { t.Fatal("fail mode read without a config"); return "" })
	codex := block["codex"]
	if !codex.Enabled || codex.HooksInstalled != HooksInstalledUnknown || codex.Targets != nil ||
		codex.EffectiveMode != "" || codex.EffectiveHookFailMode != "" || codex.Detected == nil || !*codex.Detected {
		t.Fatalf("codex = %+v", codex)
	}
	if amp := block["amp"]; amp.Enabled || amp.Detected != nil || amp.ManagedHook != nil {
		t.Fatalf("amp (exempt row, no config) = %+v", amp)
	}
	if _, ok := block["unknownagent"]; ok {
		t.Fatal("an id the registry does not know is listed")
	}
	if block, _ := BuildConnectors(ConnectorInputs{}, nil); block != nil {
		t.Fatalf("empty inputs = %+v", block)
	}
	// The enumerator has not run: detected is absent.
	block, _ = BuildConnectors(ConnectorInputs{ConfigLoaded: true, Enabled: []string{"codex"}}, nil)
	if block["codex"].Detected != nil {
		t.Fatalf("detected without a manifest = %v", *block["codex"].Detected)
	}
}

// A connector whose hook is in vendor machine policy only (Linux and macOS
// Codex, Claude Code, Copilot, OpenCode) has no account row: detected,
// versions and targets are absent, not false and zero, and hooks_installed
// is the machine policy's coverage (GAP-0002, GAP-0004). A machine-policy
// connector with rows (Windows) is still counted from them.
func TestBuildConnectorsMachinePolicyOnly(t *testing.T) {
	in := ConnectorInputs{
		ConfigLoaded: true, Enabled: []string{"codex", "claudecode", "copilot", "opencode", "hermes"},
		Mode:         func(string) string { return "observe" },
		ManifestRead: true, Manifest: []ConnectorInstall{{Connector: "hermes", Version: "0.21.5", Enabled: true}},
		GuardianKnown: true, Guardian: []ConnectorTarget{{Connector: "hermes", OK: true}},
		MachinePolicy: []string{"codex", "claudecode", "copilot", "opencode"},
		MachinePolicyCoverage: map[string]string{"codex": HooksInstalledAll, "claudecode": HooksInstalledNone,
			"copilot": HooksInstalledPartial, "opencode": "bogus"},
	}
	block, _ := BuildConnectors(in, func(string) string { return "closed" })
	want := map[string]ConnectorState{
		"codex":      {Enabled: true, HooksInstalled: HooksInstalledAll, EffectiveMode: "observe", EffectiveHookFailMode: "closed", ManagedHook: boolPtr(true)},
		"claudecode": {Enabled: true, HooksInstalled: HooksInstalledNone, EffectiveMode: "observe", EffectiveHookFailMode: "closed", ManagedHook: boolPtr(true)},
		"copilot":    {Enabled: true, HooksInstalled: HooksInstalledPartial, EffectiveMode: "observe", EffectiveHookFailMode: "closed", ManagedHook: boolPtr(true)},
		"opencode":   {Enabled: true, HooksInstalled: HooksInstalledUnknown, EffectiveMode: "observe", EffectiveHookFailMode: "closed", ManagedHook: boolPtr(true)},
		"hermes": {Enabled: true, Detected: boolPtr(true), Versions: []string{"0.21.5"}, HooksInstalled: HooksInstalledAll,
			Targets: &ConnectorTargets{Total: 1, Protected: 1}, EffectiveMode: "observe", EffectiveHookFailMode: "closed", ManagedHook: boolPtr(false)},
	}
	if !reflect.DeepEqual(block, want) {
		got, _ := json.MarshalIndent(block, "", " ")
		t.Fatalf("block:\n%s", got)
	}
	// With rows, the rows count.
	in.Manifest = append(in.Manifest, ConnectorInstall{Connector: "codex", Version: "0.160.0", Enabled: true})
	in.Guardian = append(in.Guardian, ConnectorTarget{Connector: "codex"})
	block, _ = BuildConnectors(in, nil)
	if codex := block["codex"]; codex.Detected == nil || !*codex.Detected || codex.Targets == nil || codex.Targets.Failed != 1 ||
		codex.HooksInstalled != HooksInstalledNone {
		t.Fatalf("codex with rows = %+v", codex)
	}
}

// A machine-policy-only connector with no manifest target can still have an
// unprotected install (an unenrolled_users: deny user the enumerator could
// not enroll, or a refused surface): it is detected, with its versions, and
// hooks_installed still comes from the machine policy, not a false none from
// zero targets.
func TestBuildConnectorsMachinePolicyOnlyWithUnprotectedInstall(t *testing.T) {
	in := ConnectorInputs{
		ConfigLoaded: true, Enabled: []string{"codex"},
		Mode:         func(string) string { return "observe" },
		ManifestRead: true, Unprotected: []ConnectorInstall{{Connector: "codex", Version: "0.160.0"}},
		GuardianKnown: true, MachinePolicy: []string{"codex"},
		MachinePolicyCoverage: map[string]string{"codex": HooksInstalledAll},
	}
	block, _ := BuildConnectors(in, func(string) string { return "closed" })
	want := ConnectorState{Enabled: true, Detected: boolPtr(true), Versions: []string{"0.160.0"}, HooksInstalled: HooksInstalledAll,
		EffectiveMode: "observe", EffectiveHookFailMode: "closed", ManagedHook: boolPtr(true)}
	if got := block["codex"]; !reflect.DeepEqual(got, want) {
		data, _ := json.MarshalIndent(got, "", " ")
		t.Fatalf("codex:\n%s", data)
	}
}

func TestBuildConnectorsBoundsVersions(t *testing.T) {
	in := ConnectorInputs{ManifestRead: true}
	for _, v := range []string{"9", "8", "7", "6", "5", "4", "3", "2", "1", "0"} {
		in.Manifest = append(in.Manifest, ConnectorInstall{Connector: "codex", Version: "1." + v, Enabled: true})
	}
	in.Manifest = append(in.Manifest, ConnectorInstall{Connector: "codex", Version: strings.Repeat("1", 65), Enabled: true},
		ConnectorInstall{Connector: "codex", Version: "/home/alice/bin/codex", Enabled: true})
	block, hidden := BuildConnectors(in, nil)
	if got := block["codex"].Versions; len(got) != connectorVersionsMax || got[0] != "1.0" || hidden != 2 {
		t.Fatalf("versions = %v hidden = %d", got, hidden)
	}
}

func TestParseIdentityHealth(t *testing.T) {
	unknown := IdentityHealth{State: IdentityStateUnknown, ReasonCode: CodeGatewayDidNotReport}
	counted := func(h IdentityHealth, failing, stale int) IdentityHealth {
		offline := stale > 0
		h.FailingAccounts, h.StaleAccounts, h.ServingOfflineCache = &failing, &stale, &offline
		return h
	}
	cases := map[string]struct {
		body string
		want IdentityHealth
	}{
		"older gateway":  {`{"ok":true}`, unknown},
		"not JSON":       {`<html>`, unknown},
		"missing counts": {`{"identity":{"sources":[]}}`, unknown},
		"idle":           {`{"identity":{"sources":[],"failing":0,"stale":0}}`, counted(IdentityHealth{State: IdentityStateIdle}, 0, 0)},
		"failing and stale": {`{"identity":{"sources":[{"source":"sssd","directory":"active_directory","last_ok_age_seconds":900}],"failing":2,"stale":1}}`,
			counted(IdentityHealth{State: IdentityStateFailing, Sources: []IdentitySource{{Source: "sssd", Directory: "active_directory", LastOKAgeSeconds: 900}}}, 2, 1)},
		"ok, bad tokens dropped": {`{"identity":{"sources":[
			{"source":"sssd","directory":"alice@example.com","last_ok_age_seconds":7},
			{"source":"nss_files","directory":"local","last_ok_age_seconds":5},
			{"source":"DOMAIN\\alice","directory":"local","last_ok_age_seconds":5},
			{"source":"winbind","last_ok_age_seconds":-1}],"failing":0,"stale":0,"accounts":["1001"]}}`,
			counted(IdentityHealth{State: IdentityStateOK, Sources: []IdentitySource{
				{Source: "nss_files", Directory: "local", LastOKAgeSeconds: 5}, {Source: "sssd", LastOKAgeSeconds: 7}}}, 0, 0)},
	}
	for name, tc := range cases {
		if got := ParseIdentityHealth([]byte(tc.body)); !reflect.DeepEqual(*got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", name, *got, tc.want)
		}
	}
	if got := IdentityGatewayNotReady(); got.State != IdentityStateUnknown || got.ReasonCode != CodeGatewayNotReady {
		t.Fatalf("not ready = %+v", got)
	}
}

func TestOpenShellConstantBlocks(t *testing.T) {
	if got := OpenShellUnsupportedCapability(); got.Enabled || got.DriverAvailable != OpenShellDriverNone || got.ReasonCode != CodePlatformUnsupported {
		t.Fatalf("unsupported = %+v", got)
	}
	if got := OpenShellDisabledCapability(); got.Enabled || got.DriverAvailable != OpenShellDriverNone || got.ReasonCode != CodeOpenShellDisabled {
		t.Fatalf("disabled = %+v", got)
	}
}
