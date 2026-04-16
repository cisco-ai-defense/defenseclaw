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
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit/sinks"
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

func (c *captureSink) Name() string                    { return "capture" }
func (c *captureSink) Kind() string                    { return "capture" }
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

// NOTE: TestLoggerRedactsPIIBeforeSink and TestLoggerSinkBypassesRevealFlag
// were removed alongside the internal/redaction scrubbing layer. PII
// redaction will be reintroduced in a follow-up PR that lives in the
// sink layer (see docs/OBSERVABILITY.md migration note).
