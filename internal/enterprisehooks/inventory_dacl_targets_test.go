// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "testing"

// A profile enrolled only by disabled rows gets no new inventory read grant;
// one with an enabled row keeps it, whatever the order (GAP-1193).
func TestInventoryDACLGrantTargetsSkipDisabledOnlyProfiles(t *testing.T) {
	off, on := false, true
	manifest := Manifest{Targets: []ManifestTarget{
		{SID: "S-1-5-21-1-2-3-1001", UserHome: `C:\Users\alice`, Connector: "codex", Enabled: &off},
		{SID: "S-1-5-21-1-2-3-1002", UserHome: `C:\Users\bob`, Connector: "codex", Enabled: &off},
		{SID: "S-1-5-21-1-2-3-1002", UserHome: `C:\Users\bob`, Connector: "claudecode", Enabled: &on},
		{SID: "S-1-5-21-1-2-3-1003", UserHome: `C:\Users\carol`, Connector: "codex"},
		{SID: "S-1-5-21-1-2-3-1003", UserHome: `c:\users\CAROL`, Connector: "claudecode"},
		{SID: "S-1-5-21-1-2-3-1004", UserHome: "  ", Connector: "codex"},
	}}
	got := inventoryDACLGrantTargets(manifest)
	if len(got) != 2 || got[0].Connector != "claudecode" || got[0].SID != "S-1-5-21-1-2-3-1002" ||
		got[1].SID != "S-1-5-21-1-2-3-1003" {
		t.Fatalf("grant targets = %+v, want bob's enabled row and carol's first row only", got)
	}
}
