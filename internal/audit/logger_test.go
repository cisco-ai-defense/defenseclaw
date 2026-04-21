// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit/sinks"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// captureSink is an in-memory sinks.Sink that records every event
// the Logger forwards, used by the audit-fanout tests to assert that
// events reach the sink fan-out path with the expected fields.
//
// The previous Splunk-specific tests asserted the same invariants
// against the old SplunkForwarder; this generic capture sink replaces
// them and works against any future sink implementation by virtue of
// living one layer above the wire format.
type captureSink struct {
	mu              sync.Mutex
	events          []sinks.Event
	flushImmediate  []string
	immediateFlushC chan struct{}
}

func newCaptureSink() *captureSink {
	return &captureSink{immediateFlushC: make(chan struct{}, 16)}
}

func (c *captureSink) Name() string { return "capture" }
func (c *captureSink) Kind() string { return "capture" }
func (c *captureSink) Forward(_ context.Context, e sinks.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}
func (c *captureSink) Flush(_ context.Context) error {
	select {
	case c.immediateFlushC <- struct{}{}:
	default:
	}
	return nil
}
func (c *captureSink) Close() error { return nil }

func (c *captureSink) snapshot() []sinks.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]sinks.Event, len(c.events))
	copy(out, c.events)
	return out
}

// installCaptureSink wires a captureSink into the Logger via a
// sinks.Manager. Callers receive the underlying sink for assertions.
func installCaptureSink(t *testing.T, l *Logger) *captureSink {
	t.Helper()
	mgr := sinks.NewManager()
	cs := newCaptureSink()
	mgr.Register(cs)
	l.SetSinks(mgr)
	return cs
}

func TestInferTargetType(t *testing.T) {
	tests := []struct {
		scanner string
		want    string
	}{
		{"skill-scanner", "skill"},
		{"skill_scanner", "skill"},
		{"mcp-scanner", "mcp"},
		{"mcp_scanner", "mcp"},
		{"codeguard", "code"},
		{"aibom", "code"},
		{"aibom-claw", "code"},
		{"clawshield-vuln", "code"},
		{"clawshield-secrets", "code"},
		{"clawshield-pii", "code"},
		{"clawshield-malware", "code"},
		{"clawshield-injection", "code"},
		{"future-scanner", "unknown"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			if got := inferTargetType(tt.scanner); got != tt.want {
				t.Errorf("inferTargetType(%q) = %q, want %q", tt.scanner, got, tt.want)
			}
		})
	}
}

func TestInferAssetTypeFromAction(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		details string
		want    string
	}{
		{"mcp action", "mcp-block", "", "mcp"},
		{"mcp in details", "block", "type=mcp reason=test", "mcp"},
		{"skill action", "skill-install", "", "skill"},
		{"skill in details", "install-clean", "type=skill scanner=x", "skill"},
		{"default to skill", "block", "reason=test", "skill"},
		{"watcher-block skill", "watcher-block", "type=skill reason=x", "skill"},
		{"watcher-block mcp", "watcher-block", "type=mcp reason=x", "mcp"},
		{"empty action", "", "", "skill"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inferAssetTypeFromAction(tt.action, tt.details); got != tt.want {
				t.Errorf("inferAssetTypeFromAction(%q, %q) = %q, want %q",
					tt.action, tt.details, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"hello world", "world", true},
		{"hello", "hello", true},
		{"hello", "xyz", false},
		{"", "", true},
		{"hello", "", true},
		{"", "x", false},
		{"type=skill scanner=x", "type=skill", true},
		{"type=mcp", "type=skill", false},
	}
	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			if got := contains(tt.s, tt.substr); got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestLoggerLogActionIncludesRunID(t *testing.T) {
	t.Setenv("DEFENSECLAW_RUN_ID", "logger-run-id")

	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	if err := logger.LogAction("skill-block", "test-skill", "reason=test"); err != nil {
		t.Fatalf("LogAction: %v", err)
	}

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if got := events[0].RunID; got != "logger-run-id" {
		t.Fatalf("RunID = %q, want %q", got, "logger-run-id")
	}
}

func TestLoggerSinkForwardingIncludesDefaultedFields(t *testing.T) {
	t.Setenv("DEFENSECLAW_RUN_ID", "logger-sink-run-id")

	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	cs := installCaptureSink(t, logger)
	if err := logger.LogAction("skill-block", "test-skill", "reason=test"); err != nil {
		t.Fatalf("LogAction: %v", err)
	}
	logger.Close()

	got := cs.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 forwarded event, got %d", len(got))
	}

	evt := got[0]
	if evt.ID == "" {
		t.Fatal("forwarded event id was empty")
	}
	if evt.Actor != "defenseclaw" {
		t.Fatalf("forwarded actor = %q, want %q", evt.Actor, "defenseclaw")
	}
	if evt.RunID != "logger-sink-run-id" {
		t.Fatalf("forwarded run_id = %q, want %q", evt.RunID, "logger-sink-run-id")
	}
	if evt.Action != "skill-block" || evt.Target != "test-skill" {
		t.Fatalf("forwarded event mismatch: %+v", evt)
	}
}

func TestLoggerForwardGatewayEvent_ForwardsStructuredPayload(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	cs := installCaptureSink(t, logger)

	logger.ForwardGatewayEvent(gatewaylog.Event{
		Timestamp: time.Now().UTC(),
		EventType: gatewaylog.EventVerdict,
		Severity:  gatewaylog.SeverityHigh,
		Model:     "gpt-4",
		RunID:     "run-123",
		Verdict: &gatewaylog.VerdictPayload{
			Stage:  gatewaylog.StageFinal,
			Action: "block",
			Reason: "matched: SEC-AWS:<redacted-pii sha256:abc123>",
		},
	})
	logger.Close()

	got := cs.snapshot()
	if len(got) != 1 {
		t.Fatalf("forwarded event count=%d want 1", len(got))
	}
	evt := got[0]
	if evt.Action != "gateway-verdict" {
		t.Fatalf("action=%q want gateway-verdict", evt.Action)
	}
	if evt.Target != "gpt-4" {
		t.Fatalf("target=%q want gpt-4", evt.Target)
	}
	if evt.Actor != "defenseclaw-gateway" {
		t.Fatalf("actor=%q want defenseclaw-gateway", evt.Actor)
	}
	if evt.RunID != "run-123" {
		t.Fatalf("run_id=%q want run-123", evt.RunID)
	}
	if evt.Structured["event_type"] != "verdict" {
		t.Fatalf("structured event_type=%v want verdict", evt.Structured["event_type"])
	}
	verdict, ok := evt.Structured["verdict"].(map[string]any)
	if !ok {
		t.Fatalf("structured verdict payload missing: %#v", evt.Structured)
	}
	if verdict["action"] != "block" {
		t.Fatalf("structured verdict action=%v want block", verdict["action"])
	}
	if !strings.Contains(evt.Details, "stage=final") {
		t.Fatalf("details=%q missing stage summary", evt.Details)
	}
}

func TestLoggerForwardGatewayEvent_ImmediateFlushForGatewayVerdict(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	cs := installCaptureSink(t, logger)

	logger.ForwardGatewayEvent(gatewaylog.Event{
		Timestamp: time.Now().UTC(),
		EventType: gatewaylog.EventVerdict,
		Severity:  gatewaylog.SeverityHigh,
		Verdict: &gatewaylog.VerdictPayload{
			Stage:  gatewaylog.StageFinal,
			Action: "block",
		},
	})

	deadline := time.After(2 * time.Second)
	select {
	case <-cs.immediateFlushC:
	case <-deadline:
		t.Fatal("expected gateway-verdict to trigger immediate sink flush")
	}
}

func TestLoggerSinkFlushesWatchStartImmediately(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	cs := installCaptureSink(t, logger)

	if err := logger.LogAction("watch-start", "", "dirs=3 debounce=500ms"); err != nil {
		t.Fatalf("LogAction: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if len(cs.snapshot()) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if len(cs.snapshot()) == 0 {
		t.Fatal("expected watch-start to be forwarded to the sink promptly")
	}
}

func TestLoggerLogEventPreservesSeverity(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	evt := Event{
		Action:   "drift",
		Target:   "/path/to/skill",
		Actor:    "defenseclaw-rescan",
		Details:  "hash changed",
		Severity: "HIGH",
	}
	if err := logger.LogEvent(evt); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if got := events[0].Severity; got != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", got)
	}
	if events[0].ID == "" {
		t.Fatal("expected ID to be auto-filled")
	}
}

func TestLoggerLogEventSinkForwarding(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	cs := installCaptureSink(t, logger)

	evt := Event{
		Action:   "drift",
		Target:   "/path/to/skill",
		Actor:    "defenseclaw-rescan",
		Details:  "new finding",
		Severity: "CRITICAL",
	}
	if err := logger.LogEvent(evt); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}
	logger.Close()

	got := cs.snapshot()
	if len(got) == 0 {
		t.Fatal("expected drift event to be forwarded to the sink")
	}
	if got[0].Action != "drift" {
		t.Fatalf("action = %q, want drift", got[0].Action)
	}
	if got[0].Severity != "CRITICAL" {
		t.Fatalf("severity = %q, want CRITICAL", got[0].Severity)
	}
}

// TestLoggerRedactsPIIBeforeSink asserts the redaction invariant for
// the audit fan-out path: free-form Details strings with phone
// numbers, emails, or SSNs never reach the sink channel or SQLite in
// plaintext, regardless of which Log* entrypoint the caller used.
//
// Any of these leaking to a persistent sink is an incident, so the
// test brackets every Log* method rather than trusting transitive
// coverage.
func TestLoggerRedactsPIIBeforeSink(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")

	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	cs := installCaptureSink(t, logger)

	cases := []struct {
		name   string
		record func() error
		pii    []string
	}{
		{
			name: "LogAction phone in details",
			record: func() error {
				return logger.LogAction("tool-call", "sms-tool",
					"args.recipient=4155551234")
			},
			pii: []string{"4155551234"},
		},
		{
			name: "LogActionWithTrace email in details",
			record: func() error {
				return logger.LogActionWithTrace("skill-install", "contacts",
					"user=alice@example.com", "trace-xyz")
			},
			pii: []string{"alice@example.com"},
		},
		{
			name: "LogEvent SSN in details",
			record: func() error {
				return logger.LogEvent(Event{
					Action:   "tool-call",
					Target:   "ssn-lookup",
					Details:  "args.ssn=123-45-6789",
					Severity: "HIGH",
				})
			},
			pii: []string{"123-45-6789"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			before := len(cs.snapshot())
			if err := tc.record(); err != nil {
				t.Fatalf("record: %v", err)
			}
			snap := cs.snapshot()
			if len(snap) <= before {
				t.Fatalf("expected new sink event; got %d total", len(snap))
			}
			sinkEvt := snap[len(snap)-1]
			for _, needle := range tc.pii {
				if strings.Contains(sinkEvt.Details, needle) {
					t.Fatalf("sink leaked PII %q in Details=%q",
						needle, sinkEvt.Details)
				}
			}

			// SQLite leg: ListEvents pulls the row we just inserted;
			// its Details must also be redacted.
			events, err := store.ListEvents(32)
			if err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			// ListEvents returns newest first.
			for _, needle := range tc.pii {
				if strings.Contains(events[0].Details, needle) {
					t.Fatalf("SQLite leaked PII %q in Details=%q",
						needle, events[0].Details)
				}
			}
		})
	}
}

// TestLoggerSinkBypassesRevealFlag confirms that persistent sinks
// remain fully redacted even when the operator has set
// DEFENSECLAW_REVEAL_PII=1 on the host for triage. The reveal flag
// is strictly scoped to stderr/TUI; the audit store, audit sinks,
// and OTel exporters must never unmask.
func TestLoggerSinkBypassesRevealFlag(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")

	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	cs := installCaptureSink(t, logger)

	if err := logger.LogAction("tool-call", "sms-tool",
		"args.recipient=4155551234"); err != nil {
		t.Fatalf("LogAction: %v", err)
	}

	snap := cs.snapshot()
	if len(snap) == 0 {
		t.Fatal("no sink event")
	}
	if strings.Contains(snap[0].Details, "4155551234") {
		t.Fatalf("sink unmasked under reveal flag: %q", snap[0].Details)
	}

	events, _ := store.ListEvents(10)
	if len(events) > 0 && strings.Contains(events[0].Details, "4155551234") {
		t.Fatalf("SQLite unmasked under reveal flag: %q", events[0].Details)
	}
}

// TestLoggerRedactsFindingFieldsBeforeSQLite covers the scan-result
// path: a Finding whose Description/Location/Remediation contain PII
// must reach SQLite only as "<redacted ...>" placeholders. The
// finding title is authored from static rule metadata so it stays
// verbatim.
func TestLoggerRedactsFindingFieldsBeforeSQLite(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")

	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	result := &scanner.ScanResult{
		Scanner:   "clawshield-pii",
		Target:    "test-skill",
		Timestamp: time.Now(),
		Duration:  time.Millisecond,
		Findings: []scanner.Finding{
			{
				Severity:    scanner.SeverityHigh,
				Title:       "PII detected",
				Description: "detected SSN 123-45-6789 in payload",
				Location:    "/home/alice@example.com/skill.py:42",
				Remediation: "contact 4155551234 before removing",
				Scanner:     "clawshield-pii",
			},
		},
	}
	if err := logger.LogScan(result); err != nil {
		t.Fatalf("LogScan: %v", err)
	}

	scans, err := store.ListScanResults(10)
	if err != nil {
		t.Fatalf("ListScanResults: %v", err)
	}
	if len(scans) == 0 {
		t.Fatal("expected a scan row")
	}
	findings, err := store.ListFindingsByScan(scans[0].ID)
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding row")
	}
	f := findings[0]
	for _, needle := range []string{"123-45-6789", "4155551234", "alice@example.com"} {
		if strings.Contains(f.Description, needle) ||
			strings.Contains(f.Location, needle) ||
			strings.Contains(f.Remediation, needle) {
			t.Fatalf("SQLite finding leaked %q: desc=%q loc=%q rem=%q",
				needle, f.Description, f.Location, f.Remediation)
		}
	}
	if f.Title != "PII detected" {
		t.Fatalf("Title should be preserved verbatim; got %q", f.Title)
	}
}
