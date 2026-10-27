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
