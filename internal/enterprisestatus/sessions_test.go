// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"bytes"
	"errors"
	"strings"
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
		name     string
		changed  map[string]time.Time
		wantPIDs []int
	}{
		{"before managed settings", map[string]time.Time{"claudecode": changed, "codex": changed}, []int{41, 43}},
		{"other connector not installed", map[string]time.Time{"cursor": changed}, []int{44}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UnprotectedSessions(rows, tc.changed)
			if got.State != "known" || got.Count != len(tc.wantPIDs) || len(got.Entries) != len(tc.wantPIDs) {
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
	got := UnprotectedSessions(more, map[string]time.Time{"claudecode": changed})
	if got.Count != 25 || len(got.Entries) != 20 {
		t.Fatalf("bounded entries = %+v", got)
	}
}

func TestScanSessionsUsesProcessListerAndExplainsFailure(t *testing.T) {
	changed := time.Date(2026, 10, 13, 7, 9, 0, 0, time.UTC)
	lister := func() ([]SessionProcess, error) {
		return []SessionProcess{{PID: 8664, User: "dcw-std1", Agent: "claudecode", StartedAt: changed.Add(-time.Minute)}}, nil
	}
	got := ScanSessions(lister, map[string]time.Time{"claudecode": changed}, true)
	if got.State != "known" || got.Count != 1 || got.Entries[0].PID != 8664 || got.Entries[0].User != "dcw-std1" || got.Entries[0].StartedAt == "" {
		t.Fatalf("old session = %+v", got)
	}
	if code, message := SessionWarning(got); code != CodeSessionsNeedRestart || !strings.Contains(message, "restart") {
		t.Fatalf("warning = %s: %s", code, message)
	}
	var printed bytes.Buffer
	WriteSessionEntries(&printed, got)
	for _, want := range []string{"pid 8664", "user dcw-std1", "2026-10-13T07:08:00Z", "restart the agent"} {
		if !strings.Contains(printed.String(), want) {
			t.Fatalf("text omits %q: %s", want, printed.String())
		}
	}
	failed := ScanSessions(func() ([]SessionProcess, error) { return nil, errors.New("process snapshot failed") }, nil, true)
	if failed.State != "unknown" || failed.Count != 0 || failed.Reason != "process snapshot failed" {
		t.Fatalf("failed scan = %+v", failed)
	}
	if code, message := SessionWarning(failed); code != "sessions_scan_unknown" || !strings.Contains(message, failed.Reason) {
		t.Fatalf("unknown warning = %s: %s", code, message)
	}
	unprivileged := ScanSessions(nil, nil, false)
	if unprivileged.State != "unknown" || !strings.Contains(unprivileged.Reason, "administrator privileges") {
		t.Fatalf("unprivileged scan = %+v", unprivileged)
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

func TestUnknownBundleSessionsPreventCompleteCoverage(t *testing.T) {
	r := &Result{CoverageComplete: true, SecurityComplete: true, Bundle: &BundleState{State: BundleConfirmed}}
	r.SetBundleSessions(SessionRestartStatus{State: "unknown", Entries: []SessionEntry{}, Reason: "process snapshot failed"})
	r.Finish("windows", 0)
	if r.CoverageComplete || r.SecurityComplete || len(r.Warnings) != 1 || r.Warnings[0].Code != "sessions_scan_unknown" ||
		!strings.Contains(r.Warnings[0].Message, "process snapshot failed") {
		t.Fatalf("unknown scan was reported as complete: %+v", r)
	}
}

func TestBundleDigestUnverifiableMarkerReachesStatus(t *testing.T) {
	r := &Result{Bundle: &BundleState{State: BundleConfirmed, WarningCodes: []string{"digest_unverifiable"}}}
	r.SetBundleReceiptWarnings()
	r.SetBundleReceiptWarnings()
	if len(r.Warnings) != 1 || r.Warnings[0].Code != "digest_unverifiable" ||
		!strings.Contains(r.Warnings[0].Message, "gateway-versus-installed digest were checked") {
		t.Fatalf("digest marker omitted or duplicated: %+v", r)
	}
}

// TestUnprotectedSessionsCollapsesLauncherAndChild verifies that a script-host
// launcher and its native child process for the same user and agent collapse
// into one session entry carrying the parent launcher PID.
func TestUnprotectedSessionsCollapsesLauncherAndChild(t *testing.T) {
	changed := time.Date(2026, 10, 21, 22, 25, 0, 0, time.UTC)
	rows := []SessionProcess{
		{PID: 3706701, PPID: 1200, User: "alice", Agent: "codex", Launcher: true, StartedAt: changed.Add(-2 * time.Minute)},
		{PID: 3706708, PPID: 3706701, User: "alice", Agent: "codex", StartedAt: changed.Add(-2*time.Minute + 30*time.Millisecond)},
	}
	got := UnprotectedSessions(rows, map[string]time.Time{"codex": changed})
	if got.State != "known" || got.Count != 1 || len(got.Entries) != 1 || got.Entries[0].PID != 3706701 {
		t.Fatalf("collapsed launcher/child = %+v, want count 1 with parent pid 3706701", got)
	}
}

// TestUnprotectedSessionsKeepsIndependentSessions verifies that separate
// launcher/child pairs and separate native-agent parent/child sessions of the
// same user are counted independently.
func TestUnprotectedSessionsKeepsIndependentSessions(t *testing.T) {
	changed := time.Date(2026, 10, 21, 22, 25, 0, 0, time.UTC)
	rows := []SessionProcess{
		{PID: 1001, PPID: 500, User: "alice", Agent: "codex", Launcher: true, StartedAt: changed.Add(-3 * time.Minute)},
		{PID: 1002, PPID: 1001, User: "alice", Agent: "codex", StartedAt: changed.Add(-3 * time.Minute)},
		{PID: 2001, PPID: 600, User: "alice", Agent: "codex", Launcher: true, StartedAt: changed.Add(-2 * time.Minute)},
		{PID: 2002, PPID: 2001, User: "alice", Agent: "codex", StartedAt: changed.Add(-2 * time.Minute)},
	}
	got := UnprotectedSessions(rows, map[string]time.Time{"codex": changed})
	if got.State != "known" || got.Count != 2 || len(got.Entries) != 2 || got.Entries[0].PID != 1001 || got.Entries[1].PID != 2001 {
		t.Fatalf("independent sessions = %+v, want count 2 with pids 1001 and 2001", got)
	}

	nativePair := []SessionProcess{
		{PID: 2501, PPID: 700, User: "alice", Agent: "codex", StartedAt: changed.Add(-2 * time.Minute)},
		{PID: 2502, PPID: 2501, User: "alice", Agent: "codex", StartedAt: changed.Add(-time.Minute)},
	}
	gotNative := UnprotectedSessions(nativePair, map[string]time.Time{"codex": changed})
	if gotNative.State != "known" || gotNative.Count != 2 || len(gotNative.Entries) != 2 {
		t.Fatalf("independent native parent/child sessions = %+v, want count 2", gotNative)
	}
}

// TestUnprotectedSessionsDoesNotCollapseAcrossUserOrAgent verifies that
// parent/child processes belonging to different agents or different users are
// never merged into a single session.
func TestUnprotectedSessionsDoesNotCollapseAcrossUserOrAgent(t *testing.T) {
	changed := time.Date(2026, 10, 21, 22, 25, 0, 0, time.UTC)
	rows := []SessionProcess{
		{PID: 3001, PPID: 1, User: "alice", Agent: "claudecode", Launcher: true, StartedAt: changed.Add(-time.Minute)},
		{PID: 3002, PPID: 3001, User: "alice", Agent: "codex", StartedAt: changed.Add(-time.Minute)},
		{PID: 4001, PPID: 1, User: "alice", Agent: "codex", Launcher: true, StartedAt: changed.Add(-time.Minute)},
		{PID: 4002, PPID: 4001, User: "bob", Agent: "codex", StartedAt: changed.Add(-time.Minute)},
	}
	got := UnprotectedSessions(rows, map[string]time.Time{"claudecode": changed, "codex": changed})
	if got.State != "known" || got.Count != 4 || len(got.Entries) != 4 {
		t.Fatalf("cross-user/agent sessions = %+v, want all 4 kept", got)
	}
}

// TestUnprotectedSessionsPPIDCycleTerminates verifies that cyclic PPID
// references terminate cleanly without hanging and yield a bounded count.
func TestUnprotectedSessionsPPIDCycleTerminates(t *testing.T) {
	changed := time.Date(2026, 10, 21, 22, 25, 0, 0, time.UTC)
	rows := []SessionProcess{
		{PID: 5001, PPID: 5002, User: "alice", Agent: "codex", Launcher: true, StartedAt: changed.Add(-time.Minute)},
		{PID: 5002, PPID: 5001, User: "alice", Agent: "codex", StartedAt: changed.Add(-time.Minute)},
	}
	got := UnprotectedSessions(rows, map[string]time.Time{"codex": changed})
	if got.State != "known" || got.Count < 1 || got.Count > 2 {
		t.Fatalf("ppid cycle = %+v, want known state with count in [1,2]", got)
	}
}
