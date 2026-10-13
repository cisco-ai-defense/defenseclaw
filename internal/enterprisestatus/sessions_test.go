// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"testing"
	"time"
)

func TestUnprotectedSessions(t *testing.T) {
	changed := time.Date(2026, 10, 13, 7, 9, 0, 0, time.UTC)
	rows := []SessionProcess{
		{PID: 41, User: "alice", Agent: "claudecode", StartedAt: changed.Add(-time.Minute)},
		{PID: 42, User: "alice", Agent: "claudecode", StartedAt: changed.Add(time.Minute)},
		{PID: 43, User: "bob", Agent: "codex", StartedAt: changed.Add(-time.Minute)},
		{PID: 44, User: "bob", Agent: "cursor", StartedAt: changed.Add(-time.Minute)},
	}
	for _, tc := range []struct {
		name       string
		privileged bool
		changed    map[string]time.Time
		wantState  string
		wantPIDs   []int
	}{
		{"before managed settings", true, map[string]time.Time{"claudecode": changed, "codex": changed}, "known", []int{41, 43}},
		{"other connector not installed", true, map[string]time.Time{"cursor": changed}, "known", []int{44}},
		{"requires privileged scan", false, map[string]time.Time{"claudecode": changed}, "unknown", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UnprotectedSessions(rows, tc.changed, tc.privileged)
			if got.State != tc.wantState || got.Count != len(tc.wantPIDs) || len(got.Entries) != len(tc.wantPIDs) {
				t.Fatalf("sessions = %+v", got)
			}
			for i, pid := range tc.wantPIDs {
				if got.Entries[i].PID != pid || got.Entries[i].StartedAt == "" {
					t.Fatalf("entry %d = %+v", i, got.Entries[i])
				}
			}
		})
	}
	more := make([]SessionProcess, 25)
	for i := range more {
		more[i] = SessionProcess{PID: 100 + i, User: "alice", Agent: "claudecode", StartedAt: changed.Add(-time.Minute)}
	}
	got := UnprotectedSessions(more, map[string]time.Time{"claudecode": changed}, true)
	if got.Count != 25 || len(got.Entries) != 20 {
		t.Fatalf("bounded entries = %+v", got)
	}
}

func TestBundleSessionsPreventCompleteCoverage(t *testing.T) {
	r := &Result{CoverageComplete: true, SecurityComplete: true, Bundle: &BundleState{State: BundleConfirmed}}
	r.SetBundleSessions(SessionRestartStatus{State: "known", Count: 1, Entries: []SessionEntry{}})
	r.Finish("linux", 0)
	if r.CoverageComplete || r.SecurityComplete || len(r.Warnings) != 1 || r.Warnings[0].Code != CodeSessionsNeedRestart {
		t.Fatalf("result with old session = %+v", r)
	}
}
