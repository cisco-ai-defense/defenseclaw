// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func claudeMachineContractRow(sid, version string, enabled bool) ManifestTarget {
	return ManifestTarget{SID: sid, Connector: "claudecode", AgentVersion: version, Enabled: &enabled}
}

func TestWindowsStandaloneClaudeMachinePolicyContractIsTheOldestEnrolledContract(t *testing.T) {
	v1 := connector.ResolveHookContract("claudecode", "2.1.160").Contract.ContractID
	v2 := connector.ResolveHookContract("claudecode", "2.1.230").Contract.ContractID
	if v1 == "" || v2 == "" || v1 == v2 {
		t.Fatalf("fixture versions must resolve to two different contracts, got %q and %q", v1, v2)
	}
	codex := true
	for _, tc := range []struct {
		name     string
		manifest Manifest
		want     string
	}{
		{name: "no Claude rows", manifest: Manifest{Targets: []ManifestTarget{{SID: "S-1-5-21-1-2-3-1001", Connector: "codex", AgentVersion: "0.150.0", Enabled: &codex}}}},
		{name: "one newer row", manifest: Manifest{Targets: []ManifestTarget{claudeMachineContractRow("S-1-5-21-1-2-3-1001", "2.1.230", true)}}, want: v2},
		{name: "mixed rows", manifest: Manifest{Targets: []ManifestTarget{
			claudeMachineContractRow("S-1-5-21-1-2-3-1001", "2.1.230", true),
			claudeMachineContractRow("S-1-5-21-1-2-3-1002", "2.1.160", true),
		}}, want: v1},
		{name: "disabled older row ignored", manifest: Manifest{Targets: []ManifestTarget{
			claudeMachineContractRow("S-1-5-21-1-2-3-1001", "2.1.230", true),
			claudeMachineContractRow("S-1-5-21-1-2-3-1002", "2.1.160", false),
		}}, want: v2},
		{name: "unknown version ignored", manifest: Manifest{Targets: []ManifestTarget{
			claudeMachineContractRow("S-1-5-21-1-2-3-1001", "2.1.230", true),
			claudeMachineContractRow("S-1-5-21-1-2-3-1002", "1.0.0", true),
		}}, want: v2},
	} {
		if got := WindowsStandaloneClaudeMachinePolicyContract(tc.manifest); got != tc.want {
			t.Errorf("%s: contract = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Every row of one manifest renders the machine-wide body from the same
// contract, whatever its own version, and only in a standalone process.
func TestClaudeMachinePolicySetupIsIndependentOfTheRowVersion(t *testing.T) {
	manifest := Manifest{Targets: []ManifestTarget{
		claudeMachineContractRow("S-1-5-21-1-2-3-1001", "2.1.230", true),
		claudeMachineContractRow("S-1-5-21-1-2-3-1002", "2.1.160", true),
	}}
	machine := WindowsStandaloneClaudeMachinePolicyContract(manifest)
	var chosen []string
	for _, target := range manifest.Targets {
		row := connector.SetupOpts{
			AgentVersion:   target.AgentVersion,
			HookContractID: connector.ResolveHookContract("claudecode", target.AgentVersion).Contract.ContractID,
		}
		chosen = append(chosen, claudeMachinePolicySetup(row, machine, true).HookContractID)
		if got := claudeMachinePolicySetup(row, machine, false); got.HookContractID != row.HookContractID {
			t.Fatalf("Secure Client must render the row's own contract, got %q for %q", got.HookContractID, row.HookContractID)
		}
	}
	if chosen[0] != machine || chosen[1] != machine {
		t.Fatalf("rows rendered contracts %v, want %s for both", chosen, machine)
	}

	newerThanRow := connector.SetupOpts{HookContractID: connector.ResolveHookContract("claudecode", "2.1.160").Contract.ContractID}
	v2 := connector.ResolveHookContract("claudecode", "2.1.230").Contract.ContractID
	if got := claudeMachinePolicySetup(newerThanRow, v2, true); got.HookContractID != newerThanRow.HookContractID {
		t.Fatalf("a contract newer than the row's own must never be rendered for it, got %q", got.HookContractID)
	}
}
