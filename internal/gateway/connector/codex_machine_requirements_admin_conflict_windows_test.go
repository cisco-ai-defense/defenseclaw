// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Only a Secure Client host outside strict mode may leave Codex unhooked on
// the administrator's setting; the standalone profile and strict mode refuse.
func TestWindowsCodexAdminConflictAllowedOnlyOnSecureClientOutsideStrict(t *testing.T) {
	if managed.IsStandaloneManagedHost() {
		t.Skip("this host carries the standalone runtime descriptor")
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	if !windowsCodexAdminConflictAllowed() {
		t.Fatal("Secure Client outside strict mode refused the administrator conflict")
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if windowsCodexAdminConflictAllowed() {
		t.Fatal("strict mode allowed the administrator conflict")
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	if windowsCodexAdminConflictAllowed() {
		t.Fatal("the standalone profile allowed the administrator conflict")
	}
}

// The conflict is logged once per process as defenseclaw_degraded, naming
// the file and the setting, however many Guardian steps report it.
func TestReportWindowsCodexAdminConflictLogsOneDegradedEvent(t *testing.T) {
	previous := managed.ReportResilienceEvent
	t.Cleanup(func() { managed.ReportResilienceEvent = previous })
	type event struct {
		marker string
		fields map[string]string
	}
	var events []event
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		events = append(events, event{marker, fields})
	}
	path := filepath.Join(t.TempDir(), "requirements.toml")
	conflict := "features.hooks=false conflicts with required DefenseClaw managed hooks"
	ReportWindowsCodexAdminConflict(path, conflict)
	ReportWindowsCodexAdminConflict(path, conflict)
	if len(events) != 1 {
		t.Fatalf("logged %d events, want 1", len(events))
	}
	got := events[0]
	if got.marker != managed.MarkerDegraded ||
		got.fields["subsystem"] != "codex_requirements" ||
		got.fields["path"] != path ||
		!strings.Contains(got.fields["reason"], conflict) {
		t.Fatalf("event = %+v", got)
	}
}
