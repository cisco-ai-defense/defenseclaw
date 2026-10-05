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

package enterprisehooks

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func withStandaloneProcess(t *testing.T, standalone bool) {
	t.Helper()
	previous := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previous })
	windowsEnterpriseStandaloneProcess = func() bool { return standalone }
}

func lowestHookContract(t *testing.T, name string) string {
	t.Helper()
	lowest := ""
	for _, contract := range connector.KnownHookContracts(name) {
		floor := connector.NormalizeAgentVersion(name, contract.MinAgentVersion)
		if floor != "" && (lowest == "" || compareWindowsEnterpriseVersion(floor, lowest) < 0) {
			lowest = floor
		}
	}
	return lowest
}

func TestStandaloneAgentFloorComesFromTheHookContracts(t *testing.T) {
	if got, want := windowsEnterpriseStandaloneAgentMinimum("claudecode"), lowestHookContract(t, "claudecode"); got != want || want == "" {
		t.Fatalf("claudecode floor = %q, want the lowest Claude hook contract %q", got, want)
	}
	for name, platform := range windowsEnterpriseStandalonePlatformAgentMinimums {
		got := windowsEnterpriseStandaloneAgentMinimum(name)
		if compareWindowsEnterpriseVersion(got, platform) < 0 {
			t.Fatalf("%s floor %q fell below its platform floor %q", name, got, platform)
		}
		if contract := lowestHookContract(t, name); contract != "" && compareWindowsEnterpriseVersion(got, contract) < 0 {
			t.Fatalf("%s floor %q fell below its lowest hook contract %q", name, got, contract)
		}
	}
	if got := windowsEnterpriseStandaloneAgentMinimum("not-a-connector"); got != "" {
		t.Fatalf("unknown connector floor = %q, want ungated", got)
	}
}

func TestStandaloneAgentFloorGatesOnlyStandaloneTargets(t *testing.T) {
	floor := windowsEnterpriseStandaloneAgentMinimum("claudecode")
	withStandaloneProcess(t, true)
	if err := requireWindowsEnterpriseStandaloneAgentFloor("claudecode", "2.1.152"); err == nil || !strings.Contains(err.Error(), "below the lowest hook contract "+floor) {
		t.Fatalf("standalone Claude 2.1.152 error = %v, want the hook-contract floor %s", err, floor)
	}
	if err := requireWindowsEnterpriseStandaloneAgentFloor("claudecode", floor); err != nil {
		t.Fatalf("standalone Claude at the floor: %v", err)
	}
	withStandaloneProcess(t, false)
	if err := requireWindowsEnterpriseStandaloneAgentFloor("claudecode", "2.1.152"); err != nil {
		t.Fatalf("Secure Client processes keep their historical floor: %v", err)
	}
}

func TestStandaloneEnumeratorSkipsClientsBelowTheContractFloor(t *testing.T) {
	stubMachineWinGet(t, nil)
	home := t.TempDir()
	writeNativeClaude(t, home, 64, map[string]int{"2.1.100": 64})
	row := ManifestTarget{SID: testLocalUserSID, Connector: "claudecode", UserHome: home}
	var logged []string
	if applyStandaloneRowState(&row, nil, func(subject, reason string) { logged = append(logged, reason) }) {
		t.Fatal("a client below the lowest hook contract must not be enrolled")
	}
	if !strings.Contains(strings.Join(logged, "\n"), "below the lowest hook contract") {
		t.Fatalf("skip reason missing: %v", logged)
	}
}
