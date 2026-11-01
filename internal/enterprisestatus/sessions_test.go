// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
	if r.CoverageComplete || r.SecurityComplete || len(r.Warnings) != 2 || r.Warnings[0].Code != CodeSessionsNeedRestart ||
		r.Warnings[1].Code != CodeSecurityIncomplete || !strings.Contains(r.Warnings[1].Message, "coverage_complete is false because of: "+CodeSessionsNeedRestart) {
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

// receipt_publish_failed reaches warnings[] next to a digest marker that is
// already listed.
func TestBundleReceiptPublishFailedReachesStatus(t *testing.T) {
	r := &Result{Bundle: &BundleState{State: BundleConfirmed, WarningCodes: []string{"digest_unverifiable", "receipt_publish_failed"}}}
	r.AddWarning("digest_unverifiable", "listed earlier")
	r.SetBundleReceiptWarnings()
	r.SetBundleReceiptWarnings()
	if len(r.Warnings) != 2 || r.Warnings[1].Code != "receipt_publish_failed" ||
		!strings.Contains(r.Warnings[1].Message, "bundle status are the record") {
		t.Fatalf("publish failure omitted or duplicated: %+v", r.Warnings)
	}
}

// receipt_events_dropped reaches warnings[] once, and the gateway marker
// the lifecycle reads is the one the reporter writes (ReceiptEventReported).
func TestBundleReceiptEventsDroppedReachesStatus(t *testing.T) {
	r := &Result{Bundle: &BundleState{State: BundleFailed, WarningCodes: []string{"receipt_events_dropped"}}}
	r.SetBundleReceiptWarnings()
	r.SetBundleReceiptWarnings()
	if len(r.Warnings) != 1 || r.Warnings[0].Code != "receipt_events_dropped" || !strings.Contains(r.Warnings[0].Message, "audit log") {
		t.Fatalf("dropped events omitted or duplicated: %+v", r.Warnings)
	}
	dataDir := t.TempDir()
	const id = "r-01JA0000000000000000000007"
	if ReceiptEventReported(dataDir, id) || ReceiptEventReported(dataDir, "../x") {
		t.Fatal("an unmarked or invalid id reads as reported")
	}
	marker := filepath.Join(dataDir, ReportedMarkersDirName, id)
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("reported\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ReceiptEventReported(dataDir, id) {
		t.Fatal("a marked receipt event does not read as reported")
	}
}

// GAP-2439 (GitHub #1360): one npm Codex runs as a node launcher and the
// native codex it starts. Both match the agent, so one terminal session was
// counted twice. A launcher and its own child are one session, named by the
// launcher pid; separate sessions, other users and other agents stay apart.
func TestUnprotectedSessionsCountsALauncherAndItsChildOnce(t *testing.T) {
	changed := time.Date(2026, 10, 21, 22, 30, 0, 0, time.UTC)
	before := changed.Add(-10 * time.Minute)
	only := map[string]time.Time{"codex": changed, "claudecode": changed}
	for _, tc := range []struct {
		name     string
		rows     []SessionProcess
		wantPIDs []int
	}{
		{"launcher and child", []SessionProcess{
			{PID: 3706708, PPID: 3706701, User: "u1", Agent: "codex", StartedAt: before.Add(30 * time.Millisecond)},
			{PID: 3706701, PPID: 900, User: "u1", Agent: "codex", StartedAt: before},
		}, []int{3706701}},
		{"two sessions of one user", []SessionProcess{
			{PID: 10, PPID: 1, User: "u1", Agent: "codex", StartedAt: before},
			{PID: 11, PPID: 10, User: "u1", Agent: "codex", StartedAt: before},
			{PID: 20, PPID: 1, User: "u1", Agent: "codex", StartedAt: before},
			{PID: 21, PPID: 20, User: "u1", Agent: "codex", StartedAt: before},
		}, []int{10, 20}},
		{"another agent or user is never merged", []SessionProcess{
			{PID: 30, PPID: 1, User: "u1", Agent: "claudecode", StartedAt: before},
			{PID: 31, PPID: 30, User: "u1", Agent: "codex", StartedAt: before},
			{PID: 40, PPID: 1, User: "u1", Agent: "codex", StartedAt: before},
			{PID: 41, PPID: 40, User: "u2", Agent: "codex", StartedAt: before},
		}, []int{30, 31, 40, 41}},
		{"a deeper tree is one session", []SessionProcess{
			{PID: 50, PPID: 1, User: "u1", Agent: "codex", StartedAt: before},
			{PID: 51, PPID: 50, User: "u1", Agent: "codex", StartedAt: before},
			{PID: 52, PPID: 51, User: "u1", Agent: "codex", StartedAt: before},
		}, []int{50}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UnprotectedSessions(tc.rows, only)
			if got.State != "known" || got.Count != len(tc.wantPIDs) || len(got.Entries) != len(tc.wantPIDs) {
				t.Fatalf("sessions = %+v, want pids %v", got, tc.wantPIDs)
			}
			for i, pid := range tc.wantPIDs {
				if got.Entries[i].PID != pid {
					t.Fatalf("entry %d = %+v, want pid %d", i, got.Entries[i], pid)
				}
			}
		})
	}
}

// A parent cycle in a bad process table ends the walk and still names the
// session once, instead of hanging or dropping every process.
func TestSessionLeadersEndsAParentCycle(t *testing.T) {
	changed := time.Date(2026, 10, 21, 22, 30, 0, 0, time.UTC)
	rows := []SessionProcess{
		{PID: 7, PPID: 8, User: "u1", Agent: "codex", StartedAt: changed.Add(-time.Minute)},
		{PID: 8, PPID: 7, User: "u1", Agent: "codex", StartedAt: changed.Add(-time.Minute)},
		{PID: 9, PPID: 9, User: "u1", Agent: "codex", StartedAt: changed.Add(-time.Minute)},
	}
	done := make(chan SessionRestartStatus, 1)
	go func() { done <- UnprotectedSessions(rows, map[string]time.Time{"codex": changed}) }()
	select {
	case got := <-done:
		if got.Count != 2 || len(got.Entries) != 2 || got.Entries[0].PID != 7 || got.Entries[1].PID != 9 {
			t.Fatalf("sessions with a parent cycle = %+v, want pids 7 and 9", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a parent cycle did not end")
	}
}
