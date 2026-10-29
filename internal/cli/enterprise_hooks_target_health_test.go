// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestEnterpriseHookTargetHealthLogsOncePerStreak(t *testing.T) {
	events := captureResilienceEvents(t)
	tracker := &enterpriseHookTargetHealthTracker{}
	row := enterpriseHookReconcileRow{Connector: "Codex", SID: "s-1-5-21-1-2-3-1001", UserHome: `C:\Users\alice`}
	for i := 0; i < 3; i++ {
		tracker.observe(row, "access denied")
	}
	if len(*events) != 1 || !strings.HasPrefix((*events)[0], managed.MarkerSkip+" ") ||
		!strings.Contains((*events)[0], `unit="codex@S-1-5-21-1-2-3-1001"`) {
		t.Fatalf("events = %v", *events)
	}
	tracker.clear(row)
	tracker.observe(row, "access denied")
	if len(*events) != 2 {
		t.Fatalf("a new streak must log again: %v", *events)
	}
}

func TestEnterpriseHookTargetUnavailable(t *testing.T) {
	if !enterpriseHookTargetUnavailable(fmt.Errorf("inspect profile: %w", os.ErrNotExist)) {
		t.Fatal("a detached profile is unavailable")
	}
	if enterpriseHookTargetUnavailable(fmt.Errorf("access denied")) || enterpriseHookTargetUnavailable(nil) {
		t.Fatal("ordinary failures are not unavailability")
	}
}

func TestEnterpriseHookEnrollmentManifestDropsOnlyUnprotectedFailures(t *testing.T) {
	disabled := false
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{Connector: "codex", SID: "S-1-5-21-1-2-3-1001"},                          // succeeded
		{Connector: "codex", SID: "S-1-5-21-1-2-3-1002"},                          // failed, never protected
		{Connector: "cursor", SID: "S-1-5-21-1-2-3-1003"},                         // failed, protected before
		{Connector: "claudecode", SID: "S-1-5-21-1-2-3-1004"},                     // signed out, never protected
		{Connector: "claudecode", SID: "S-1-5-21-1-2-3-1002", Enabled: &disabled}, // disabled stays for revocation
	}}
	rows := []enterpriseHookReconcileRow{
		{Connector: "codex", SID: "S-1-5-21-1-2-3-1001", OK: true},
		{Connector: "codex", SID: "S-1-5-21-1-2-3-1002", Error: "boom"},
		{Connector: "cursor", SID: "S-1-5-21-1-2-3-1003", Error: "boom"},
		{Connector: "claudecode", SID: "S-1-5-21-1-2-3-1004", Error: "pending: signed out"},
	}
	unenrolled := map[string]struct{}{
		"codex@S-1-5-21-1-2-3-1002":      {},
		"claudecode@S-1-5-21-1-2-3-1004": {},
	}
	reduced := enterpriseHookEnrollmentManifest(manifest, rows, unenrolled)
	var kept []string
	for _, target := range reduced.Targets {
		kept = append(kept, enterpriseHookUnit(target.Connector, target.SID))
	}
	want := "codex@S-1-5-21-1-2-3-1001,cursor@S-1-5-21-1-2-3-1003,claudecode@S-1-5-21-1-2-3-1002"
	if strings.Join(kept, ",") != want {
		t.Fatalf("kept = %v, want %s", kept, want)
	}
	if len(manifest.Targets) != 5 {
		t.Fatal("input manifest was modified")
	}
}

// A SID-less target is keyed by its own user, home and data directory, so
// dropping one never drops another SID-less target of the same connector.
func TestEnterpriseHookEnrollmentManifestKeysSIDLessTargetsApart(t *testing.T) {
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{Connector: "codex", User: "alice", UserHome: `C:\Users\alice`},
		{Connector: "codex", User: "bob", UserHome: `C:\Users\bob`},
	}}
	unenrolled := map[string]struct{}{
		enterpriseHookEnrollmentUnit(manifest.Targets[1]): {},
	}
	reduced := enterpriseHookEnrollmentManifest(manifest, nil, unenrolled)
	if len(reduced.Targets) != 1 || reduced.Targets[0].User != "alice" {
		t.Fatalf("kept = %+v, want only alice", reduced.Targets)
	}
	if enterpriseHookEnrollmentUnit(manifest.Targets[0]) == enterpriseHookEnrollmentUnit(manifest.Targets[1]) {
		t.Fatal("SID-less targets share an enrollment key")
	}
}
