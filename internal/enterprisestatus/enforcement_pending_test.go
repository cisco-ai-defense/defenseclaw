// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"strings"
	"testing"
)

// enforcement_pending merges the noted sessions with the bundle scan, counts
// a session both name once, counts unlisted scan sessions and never carries
// a user name or a pid (private #11).
func TestEnforcementPendingSummarisesSessionsWithoutUsers(t *testing.T) {
	r := &Result{Bundle: &BundleState{SessionsRestartRequired: &SessionRestartStatus{State: "known", Count: 3,
		Entries: []SessionEntry{{PID: 41, User: "alice", Agent: "codex"}, {PID: 42, User: "bob", Agent: "claudecode"}}}}}
	r.NotePendingSession("codex", 41)
	r.NotePendingSession("", 77)
	r.Finish("linux", 0)
	got, err := json.Marshal(r.EnforcementPending)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"count":4,"connectors":["claudecode","codex","unknown"]}`; string(got) != want {
		t.Fatalf("enforcement_pending = %s, want %s", got, want)
	}

	none := &Result{Bundle: &BundleState{SessionsRestartRequired: &SessionRestartStatus{State: "unknown", Reason: "x"}}}
	none.Finish("windows", 0)
	if out, _ := json.Marshal(none); none.EnforcementPending != nil || strings.Contains(string(out), "enforcement_pending") {
		t.Fatalf("an unknown scan with no named session reported enforcement_pending: %s", out)
	}
	if PendingFromScan(SessionRestartStatus{State: "known"}) != nil {
		t.Fatal("an empty scan reported enforcement_pending")
	}
}
