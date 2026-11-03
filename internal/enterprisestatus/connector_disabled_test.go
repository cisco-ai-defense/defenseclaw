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
	"reflect"
	"testing"
)

// TestBuildConnectorsNamesAConnectorTheConfigTurnsOff is rel-1-0-6:GAP-0325:
// guardrail.connectors.codex.enabled false left Codex out of status
// entirely, so nothing said it was off. It is now listed with enabled false,
// both with and without guardian state, and the text line names it
// disabled. A disabled name the config does not know is still dropped.
func TestBuildConnectorsNamesAConnectorTheConfigTurnsOff(t *testing.T) {
	failMode := func(string) string { return "closed" }
	mode := func(string) string { return "action" }
	for _, guardianKnown := range []bool{false, true} {
		in := ConnectorInputs{
			ConfigLoaded: true, Enabled: []string{"claudecode"}, Disabled: []string{"codex", "Bogus Name", "claudecode"}, Mode: mode,
			GuardianKnown: guardianKnown, MachinePolicy: []string{"claudecode"},
			MachinePolicyCoverage: map[string]string{"claudecode": HooksInstalledAll},
		}
		block, _ := BuildConnectors(in, failMode)
		codex, ok := block["codex"]
		if !ok || codex.Enabled || codex.ManagedHook != nil || codex.Detected != nil {
			t.Fatalf("guardian known %v: codex = %+v (ok=%v), want listed with enabled false", guardianKnown, codex, ok)
		}
		wantHooks := HooksInstalledUnknown
		var wantTargets *ConnectorTargets
		if guardianKnown {
			wantHooks, wantTargets = HooksInstalledNone, &ConnectorTargets{}
		}
		if codex.HooksInstalled != wantHooks || !reflect.DeepEqual(codex.Targets, wantTargets) {
			t.Fatalf("guardian known %v: codex hooks %q targets %+v", guardianKnown, codex.HooksInstalled, codex.Targets)
		}
		if claude := block["claudecode"]; !claude.Enabled {
			t.Fatalf("an enabled connector also named in Disabled stays enabled: %+v", claude)
		}
		if len(block) != 2 {
			t.Fatalf("block = %+v, want claudecode and codex only", block)
		}
		want := "connectors: claudecode enabled, codex disabled (DefenseClaw does not inspect a disabled connector on this computer)"
		if got := ConnectorsLine(block); got != want {
			t.Fatalf("line = %q\nwant %q", got, want)
		}
	}
	// Without the config nothing says the connector is off.
	block, _ := BuildConnectors(ConnectorInputs{Disabled: []string{"codex"}}, failMode)
	if _, ok := block["codex"]; ok {
		t.Fatalf("an unloaded config must not list disabled connectors: %+v", block)
	}
	if got := ConnectorsLine(nil); got != "" {
		t.Fatalf("no block, no line: %q", got)
	}
	if got := ConnectorsLine(map[string]ConnectorState{"codex": {Enabled: true}}); got != "connectors: codex enabled" {
		t.Fatalf("all-enabled line = %q", got)
	}
	// Review finding 3: an entry with enabled false that the config does
	// not turn off (a leftover guardian target, an unreadable config) is
	// "not enabled", never "disabled".
	leftover, _ := BuildConnectors(ConnectorInputs{
		ConfigLoaded: true, Enabled: []string{"claudecode"}, Disabled: []string{"codex"},
		GuardianKnown: true, Guardian: []ConnectorTarget{{Connector: "cursor", OK: true}},
	}, failMode)
	want := "connectors: claudecode enabled, codex disabled, cursor not enabled (DefenseClaw does not inspect a disabled connector on this computer)"
	if got := ConnectorsLine(leftover); got != want {
		t.Fatalf("leftover line = %q\nwant %q", got, want)
	}
	unread, _ := BuildConnectors(ConnectorInputs{Disabled: []string{"codex"}, ManifestRead: true,
		Manifest: []ConnectorInstall{{Connector: "codex"}}}, failMode)
	if got := ConnectorsLine(unread); got != "connectors: codex not enabled" {
		t.Fatalf("unread-config line = %q", got)
	}
}
