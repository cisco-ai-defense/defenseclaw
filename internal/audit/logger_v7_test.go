// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

func newTestLogger(t *testing.T) *Logger {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return NewLogger(store)
}

// TestLogActivityPersists pins the Track 0 stub contract: an
// activity mutation ends up in audit_events with a JSON-encoded
// details blob that preserves actor / action / target / diff so
// parallel tracks (which rely on this pipeline being live today)
// don't have to backfill against old rows.
func TestLogActivityPersists(t *testing.T) {
	l := newTestLogger(t)
	err := l.LogActivity(ActivityInput{
		Actor:      "cli:alice",
		Action:     ActionPolicyReload,
		TargetType: "policy",
		TargetID:   "default",
		Reason:     "manual reload",
		Before:     map[string]any{"version": "1"},
		After:      map[string]any{"version": "2"},
		Diff: []ActivityDiffEntry{
			{Path: "version", Op: "replace", Before: "1", After: "2"},
		},
		VersionFrom: "1",
		VersionTo:   "2",
	})
	if err != nil {
		t.Fatalf("LogActivity: %v", err)
	}

	events, err := l.store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Action != string(ActionPolicyReload) {
		t.Errorf("action = %q, want %q", e.Action, ActionPolicyReload)
	}
	if e.Actor != "cli:alice" {
		t.Errorf("actor = %q, want cli:alice", e.Actor)
	}
	if e.Target != "policy:default" {
		t.Errorf("target = %q, want policy:default", e.Target)
	}
	// Details is redacted by sanitizeEvent so we only assert it's
	// non-empty. Track 6 lands the native activity_events row
	// which preserves the full before/after snapshot bypassing
	// the sanitizer.
	if e.Details == "" {
		t.Errorf("details empty; want redacted non-empty blob")
	}
}

// TestLogActivityDefaults ensures the stub normalizes missing
// actor / action / severity so callers don't have to; parallel
// tracks can hand us partially populated ActivityInput values and
// still get a well-formed audit row.
//
// The action fallback MUST be a registered constant from
// AllActions() — otherwise the row will be rejected by downstream
// schema validators (schemas/audit-event.json) and by IsKnownAction
// call sites. ActionAction is the generic-mutation slot and is
// the correct fallback when the caller didn't specify what kind of
// mutation triggered the activity.
func TestLogActivityDefaults(t *testing.T) {
	l := newTestLogger(t)
	if err := l.LogActivity(ActivityInput{}); err != nil {
		t.Fatalf("LogActivity empty: %v", err)
	}
	events, err := l.store.ListEvents(1)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if events[0].Actor != "system" {
		t.Errorf("actor default = %q, want system", events[0].Actor)
	}
	if events[0].Action != string(ActionAction) {
		t.Errorf("action default = %q, want %q", events[0].Action, string(ActionAction))
	}
	if !IsKnownAction(events[0].Action) {
		t.Errorf("action default %q is not registered in AllActions()", events[0].Action)
	}
	if events[0].Severity != "INFO" {
		t.Errorf("severity default = %q, want INFO", events[0].Severity)
	}
}

// TestLogAlertPersists pins the Track 0 stub contract for runtime
// alerts — subsystem source + summary preserved, severity
// defaults to WARN, action = ActionAlert.
func TestLogAlertPersists(t *testing.T) {
	l := newTestLogger(t)
	if err := l.LogAlert("scanner", "HIGH", "skill-scanner timed out",
		map[string]any{"scanner": "skill", "duration_ms": 30000}); err != nil {
		t.Fatalf("LogAlert: %v", err)
	}
	events, err := l.store.ListEvents(1)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	e := events[0]
	if e.Action != string(ActionAlert) {
		t.Errorf("action = %q, want %q", e.Action, ActionAlert)
	}
	if e.Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", e.Severity)
	}
	// Details is redacted by sanitizeEvent so just assert
	// non-empty; Track 7 observability sink asserts the summary
	// reaches the /alerts endpoint unredacted.
	if e.Details == "" {
		t.Errorf("details empty; want redacted non-empty blob")
	}
}

// TestLogAlertSeverityDefault ensures a blank severity defaults
// to WARN so accidental zero-values don't produce INFO alerts in
// the TUI.
func TestLogAlertSeverityDefault(t *testing.T) {
	l := newTestLogger(t)
	if err := l.LogAlert("scanner", "", "something happened", nil); err != nil {
		t.Fatalf("LogAlert: %v", err)
	}
	events, err := l.store.ListEvents(1)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if events[0].Severity != "WARN" {
		t.Errorf("severity = %q, want WARN", events[0].Severity)
	}
}
