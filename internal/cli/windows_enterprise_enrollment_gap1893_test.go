// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// GAP-1893: status listed an account skipped for a per-user DefenseClaw
// install (GAP-1733) as failed for every connector, while the totals said
// failed=0 and verify passed. Its connectors read skipped and its reason says
// skipped; once the per-user install is gone the rows read failed again until
// the guardian's next pass.
func TestGAP1893StatusShowsAPerUserInstallSkipAsSkipped(t *testing.T) {
	const alice, bob = "S-1-5-21-111-222-333-1001", "S-1-5-21-111-222-333-1002"
	previous := enterpriseHookPerUserInstallFolder
	t.Cleanup(func() { enterpriseHookPerUserInstallFolder = previous })
	perUser := true
	enterpriseHookPerUserInstallFolder = func(home, sid string) bool { return perUser && sid == bob }
	rows := []enterpriseHookReconcileRow{
		{User: "alice", SID: alice, UserHome: `C:\Users\alice`, Connector: "claudecode", OK: true},
		{User: "bob", SID: bob, UserHome: `C:\Users\bob`, Connector: "claudecode", Error: enterpriseHookAccountPerUserInstallFailure},
		{User: "bob", SID: bob, UserHome: `C:\Users\bob`, Connector: "copilot", Error: enterpriseHookAccountPerUserInstallFailure},
	}
	find := func() (string, map[string]string) {
		for _, account := range windowsEnterpriseEnrollmentAccounts(rows) {
			if account.SID == bob {
				return account.Reason, account.Connectors
			}
		}
		t.Fatal("bob is not listed")
		return "", nil
	}
	reason, states := find()
	if states["claudecode"] != "skipped" || states["copilot"] != "skipped" {
		t.Fatalf("states = %v, want skipped for both connectors", states)
	}
	if strings.Contains(reason, "failed") || !strings.HasPrefix(reason, "skipped: claudecode: ") ||
		!strings.Contains(reason, "per-user DefenseClaw install") {
		t.Fatalf("reason = %q, want the skip reason and no failure", reason)
	}
	perUser = false
	reason, states = find()
	if states["claudecode"] != "failed" || !strings.HasPrefix(reason, "failed: claudecode: ") {
		t.Fatalf("after the per-user install is removed: states = %v reason = %q, want failed", states, reason)
	}
}
