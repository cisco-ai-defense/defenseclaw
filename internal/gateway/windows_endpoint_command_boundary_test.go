// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestZZCXRV1194Table pins the independent review's multi-command rows at the
// Windows Codex hook boundary. A sibling command cannot erase a finding that
// an exact command already proved (rel-1-0-10:GAP-1194).
func TestZZCXRV1194Table(t *testing.T) {
	const endpointRule = "tamper.endpoint_security_product_disable"
	rows := []struct {
		id, command string
		endpoint    bool
	}{
		{"S01", `sysmon.exe -u; Write-Output ok`, true},
		{"S02", `Write-Output ok; sysmon.exe -u`, true},
		{"S03", "sysmon.exe -u\nWrite-Output ok", true},
		{"S04", `sysmon.exe -u; sc.exe query WinDefend`, true},
		{"S05", `sysmon.exe -u; sc.exe stop WinDefend`, true},
		{"C01", `sysmon.exe -u`, true},
		{"C02", `sc.exe query WinDefend`, false},
		{"C03", `sc.exe stop Spooler`, false},
		{"C04", `Write-Output ok; sc.exe query WinDefend`, false},
		{"C05", `sc stop WinDefend`, false},
	}
	tiers := []struct {
		name, pack, endpointAction string
		managed                    bool
	}{
		{"default", "default", "alert", false},
		{"permissive", "permissive", "alert", false},
		{"strict", "strict", "block", false},
		{"managed", "default", "alert", true},
		{"managed-strict", "strict", "block", true},
	}
	root := windowsLiveShapePacks(t)
	for _, tier := range tiers {
		packDir := filepath.Join(root, tier.pack)
		for _, row := range rows {
			t.Run(tier.name+"/"+row.id, func(t *testing.T) {
				got := postWindowsCodexLiveShapeTier(t, packDir, row.command, tier.managed)
				wantAction := "allow"
				if row.endpoint {
					wantAction = tier.endpointAction
				}
				if got.Action != wantAction || slices.Contains(got.RuleIDs, endpointRule) != row.endpoint {
					t.Errorf("command %q: got %+v, want action %s and endpoint=%t", row.command, got, wantAction, row.endpoint)
				}
			})
		}
	}
}
