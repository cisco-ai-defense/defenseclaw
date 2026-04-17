// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// TestHumanizeAlertDetails_EmptyAndPlain covers the two fast paths:
// empty input returns empty, and tokens with no '=' pass through
// untouched. Together they guarantee we never mangle human-written
// free-form notes that happen to lack key=value.
func TestHumanizeAlertDetails_EmptyAndPlain(t *testing.T) {
	if got := humanizeAlertDetails(""); got != "" {
		t.Fatalf("empty: got %q want %q", got, "")
	}
	raw := "scanner failed on upload"
	if got := humanizeAlertDetails(raw); got != raw {
		t.Fatalf("plain passthrough: got %q want %q", got, raw)
	}
}

// TestHumanizeAlertDetails_HostPort covers the combined host+port
// squash (the most common gateway log), the port-only fallback, and
// the host-only fallback. These three branches are the main value
// add over raw Details so they all need explicit coverage.
func TestHumanizeAlertDetails_HostPort(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"host_and_port", "host=api.example.com port=443 mode=strict", "api.example.com:443 strict"},
		{"port_only", "port=443 mode=strict", ":443 strict"},
		{"host_only", "host=api.example.com mode=strict", "api.example.com strict"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := humanizeAlertDetails(tc.raw); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestHumanizeAlertDetails_ModelSlashTail verifies the vendor-
// prefixed model collapse (openai/gpt-4o-mini -> gpt-4o-mini) — this
// is the tail that matters when the vendor is already obvious from
// the target, and it's the exact behavior cmd_alerts.py:_humanize
// produces. A trailing slash must not strip the whole value.
func TestHumanizeAlertDetails_ModelSlashTail(t *testing.T) {
	got := humanizeAlertDetails("model=openai/gpt-4o-mini mode=strict")
	if got != "strict gpt-4o-mini" {
		t.Fatalf("got %q", got)
	}
	// No slash: pass through as-is.
	if got := humanizeAlertDetails("model=llama3"); got != "llama3" {
		t.Fatalf("no-slash: got %q", got)
	}
	// Trailing slash is pathological; keep the original to avoid
	// landing "" in the summary.
	if got := humanizeAlertDetails("model=openai/"); got != "openai/" {
		t.Fatalf("trailing-slash: got %q", got)
	}
}

// TestHumanizeAlertDetails_DropsNoise makes sure scanner, findings,
// and max_severity are dropped (they're redundant with other UI
// elements: severity badge + findings list + scanner column).
func TestHumanizeAlertDetails_DropsNoise(t *testing.T) {
	raw := "host=h port=1 mode=x scanner=skill findings=3 max_severity=HIGH"
	got := humanizeAlertDetails(raw)
	want := "h:1 x"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// TestHumanizeAlertDetails_UnknownKVAndPlainTail asserts that
// unknown key=value pairs survive at the tail (to avoid losing
// signal) and that free-floating tokens come last.
func TestHumanizeAlertDetails_UnknownKVAndPlainTail(t *testing.T) {
	raw := "host=h port=1 extra=thing tail"
	got := humanizeAlertDetails(raw)
	want := "h:1 extra=thing tail"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// TestHumanizeAlertDetails_DuplicateKeyStable guards a subtle parity
// edge: the Python implementation uses a plain dict, so a duplicate
// key keeps the last value. We instead keep the first value (stable
// ordering). Document via test so if we ever want to match Python
// exactly, a failing test will catch the drift.
func TestHumanizeAlertDetails_DuplicateKeyStable(t *testing.T) {
	got := humanizeAlertDetails("mode=first mode=second")
	if got != "first" {
		t.Fatalf("duplicate-key: got %q want %q", got, "first")
	}
}

// TestAlertsPanel_DetailEnrichment_FindingsScanner is the main
// integration test for the P3-#20 enrichment: given findings in the
// store, the rendered detail pane includes scanner name tags and
// remediation lines for each finding.
func TestAlertsPanel_DetailEnrichment_FindingsScanner(t *testing.T) {
	store := newTestAuditStore(t)
	runID := "run-p3-20"
	if err := store.LogEvent(audit.Event{
		Action:   "scan",
		Target:   "skill://demo",
		Severity: "HIGH",
		RunID:    runID,
		Details:  "host=api port=443 mode=strict model=openai/gpt-4o scanner=skill findings=2",
	}); err != nil {
		t.Fatalf("log event: %v", err)
	}
	// Seed findings against the run (scanID == runID per the
	// store's existing convention, see ListFindingsByRunID which
	// proxies to ListFindingsByScan).
	if err := store.InsertFinding(
		"f1", runID, "HIGH",
		"Hardcoded credential",
		"api token in source",
		"main.py:42",
		"Load from keychain",
		"skill-scanner",
		"",
	); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	panel := NewAlertsPanel(store)
	panel.SetSize(120, 40)
	panel.Refresh()
	if panel.FilteredCount() == 0 {
		t.Fatalf("expected alert after Refresh, got 0")
	}
	panel.SetCursor(0)
	panel.ToggleDetail()
	out := panel.View()
	for _, want := range []string{
		"Hardcoded credential",
		"main.py:42",
		"skill-scanner",
		"fix: Load from keychain",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail view missing %q. Full output:\n%s", want, out)
		}
	}
}

// TestAlertsPanel_DetailEnrichment_HumanizedSummary verifies that
// the enriched detail pane exposes both the humanized summary row
// and the raw Details row (so operators can copy exact tokens).
func TestAlertsPanel_DetailEnrichment_HumanizedSummary(t *testing.T) {
	store := newTestAuditStore(t)
	if err := store.LogEvent(audit.Event{
		Action:    "proxy",
		Target:    "gateway",
		Severity:  "MEDIUM",
		Details:   "host=api port=443 mode=strict",
		TraceID:   "trace-123",
		RequestID: "req-abc",
		Timestamp: time.Now(),
	}); err != nil {
		t.Fatalf("log: %v", err)
	}
	panel := NewAlertsPanel(store)
	panel.SetSize(120, 40)
	panel.Refresh()
	panel.SetCursor(0)
	panel.ToggleDetail()
	out := panel.View()
	for _, want := range []string{
		"Summary:", "api:443 strict",
		"Details:", "host=api port=443 mode=strict",
		"TraceID:", "trace-123",
		"ReqID:", "req-abc",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q. Output:\n%s", want, out)
		}
	}
}

// TestAlertsPanel_DetailEnrichment_HumanizedSuppressedWhenEqual
// ensures we don't render both "Summary:" and "Details:" when the
// humanize pass produces the same string (no-op) — keeps the pane
// tidy for free-form notes.
func TestAlertsPanel_DetailEnrichment_HumanizedSuppressedWhenEqual(t *testing.T) {
	store := newTestAuditStore(t)
	if err := store.LogEvent(audit.Event{
		Action:   "note",
		Target:   "ops",
		Severity: "INFO",
		Details:  "free-form without kv",
	}); err != nil {
		t.Fatalf("log: %v", err)
	}
	panel := NewAlertsPanel(store)
	panel.SetSize(120, 40)
	panel.Refresh()
	panel.SetCursor(0)
	panel.ToggleDetail()
	out := panel.View()
	if strings.Contains(out, "Summary:") {
		t.Fatalf("Summary: should be suppressed when humanize is a no-op. Output:\n%s", out)
	}
	if !strings.Contains(out, "Details:") {
		t.Fatalf("Details: should still render. Output:\n%s", out)
	}
}
