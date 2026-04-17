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

package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// readJSONLEvents reads every line in path and decodes it as a
// gatewaylog.Event. Returns an empty slice when the file does not
// exist so callers can assert "no events emitted" cleanly.
func readJSONLEvents(t *testing.T, path string) []gatewaylog.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("open jsonl: %v", err)
	}
	defer f.Close()
	var out []gatewaylog.Event
	s := bufio.NewScanner(f)
	// Allow long JSON lines — judge payloads can carry multi-KB bodies.
	s.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for s.Scan() {
		line := bytes.TrimSpace(s.Bytes())
		if len(line) == 0 {
			continue
		}
		var e gatewaylog.Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("decode jsonl line %q: %v", string(line), err)
		}
		out = append(out, e)
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan jsonl: %v", err)
	}
	return out
}

func newWriterForTest(t *testing.T) (*gatewaylog.Writer, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	w, err := gatewaylog.New(gatewaylog.Config{
		JSONLPath: path,
		// Pretty intentionally nil: keeps test output clean.
	})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, path
}

func TestAuditBridge_NilWriterSafe(t *testing.T) {
	if b := newAuditBridge(nil); b != nil {
		t.Fatalf("expected nil bridge for nil writer, got %#v", b)
	}
	// Invoking EmitAudit on a nil bridge must not panic; that's the
	// hot-path safety guarantee audit.Logger relies on.
	var b *auditBridge
	b.EmitAudit(audit.Event{Action: "sidecar-start"})
}

func TestAuditBridge_EmitsLifecycleEvent(t *testing.T) {
	w, path := newWriterForTest(t)
	b := newAuditBridge(w)

	b.EmitAudit(audit.Event{
		ID:        "evt-1",
		Timestamp: time.Now().UTC(),
		Action:    "sidecar-start",
		Target:    "",
		Actor:     "defenseclaw",
		Details:   "booting",
		Severity:  "INFO",
		RunID:     "run-123",
	})
	// Close flushes the underlying lumberjack writer.
	_ = w.Close()

	events := readJSONLEvents(t, path)
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	got := events[0]
	if got.EventType != gatewaylog.EventLifecycle {
		t.Errorf("EventType = %q, want lifecycle", got.EventType)
	}
	if got.RunID != "run-123" {
		t.Errorf("RunID = %q, want run-123", got.RunID)
	}
	if got.Lifecycle == nil {
		t.Fatalf("Lifecycle payload not populated")
	}
	if got.Lifecycle.Subsystem != "gateway" {
		t.Errorf("Subsystem = %q, want gateway", got.Lifecycle.Subsystem)
	}
	if got.Lifecycle.Transition != "start" {
		t.Errorf("Transition = %q, want start", got.Lifecycle.Transition)
	}
	if got.Lifecycle.Details["audit_id"] != "evt-1" {
		t.Errorf("audit_id = %q, want evt-1", got.Lifecycle.Details["audit_id"])
	}
}

func TestAuditBridge_SkipsGuardrailVerdict(t *testing.T) {
	w, path := newWriterForTest(t)
	b := newAuditBridge(w)

	b.EmitAudit(audit.Event{
		Action: "guardrail-verdict",
		Target: "gpt-4",
	})
	_ = w.Close()

	if events := readJSONLEvents(t, path); len(events) != 0 {
		t.Fatalf("bridge emitted a duplicate verdict row: %+v", events)
	}
}

func TestAuditBridge_SubsystemMapping(t *testing.T) {
	cases := []struct {
		action string
		want   string
	}{
		{"scan", "scanner"},
		{"watcher-block", "watcher"},
		{"watch-start", "watcher"},
		{"sidecar-start", "gateway"},
		{"gateway-ready", "gateway"},
		{"api-reload", "api"},
		{"sink-degraded", "sinks"},
		{"splunk-forwarded", "sinks"},
		{"otel-init", "telemetry"},
		{"skill-block", "enforcement"},
		{"mcp-install", "enforcement"},
		{"quarantine", "enforcement"},
		{"some-unknown-action", "gateway"},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			if got := subsystemForAction(tc.action); got != tc.want {
				t.Errorf("subsystemForAction(%q) = %q, want %q", tc.action, got, tc.want)
			}
		})
	}
}

func TestAuditBridge_SeverityNormalization(t *testing.T) {
	cases := []struct {
		in   string
		want gatewaylog.Severity
	}{
		{"", gatewaylog.SeverityInfo},
		{"INFO", gatewaylog.SeverityInfo},
		{"low", gatewaylog.SeverityLow},
		{"MEDIUM", gatewaylog.SeverityMedium},
		{"high", gatewaylog.SeverityHigh},
		{"critical", gatewaylog.SeverityCritical},
		{"garbled", gatewaylog.SeverityInfo},
		{"  HIGH  ", gatewaylog.SeverityHigh},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeAuditSeverity(tc.in); got != tc.want {
				t.Errorf("normalizeAuditSeverity(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Concurrent Emit calls must not corrupt the JSONL output. The writer
// is internally serialized; this test exists to catch any future
// change that relies on single-writer semantics at the bridge layer.
func TestAuditBridge_ConcurrentEmits(t *testing.T) {
	w, path := newWriterForTest(t)
	b := newAuditBridge(w)

	const n = 64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			b.EmitAudit(audit.Event{
				Action:   "sidecar-start",
				Target:   "",
				Severity: "INFO",
				RunID:    "concurrent-run",
			})
		}(i)
	}
	wg.Wait()
	_ = w.Close()

	events := readJSONLEvents(t, path)
	if len(events) != n {
		t.Fatalf("want %d events, got %d", n, len(events))
	}
	for _, e := range events {
		if e.EventType != gatewaylog.EventLifecycle {
			t.Fatalf("unexpected EventType %q", e.EventType)
		}
		if e.Lifecycle == nil || e.Lifecycle.Transition != "start" {
			t.Fatalf("bad lifecycle payload: %+v", e.Lifecycle)
		}
	}
}

// Sanity check: the generic "details" key carries the sanitized
// Details field verbatim, so downstream JSONL consumers can grep it.
func TestAuditBridge_DetailsForwarded(t *testing.T) {
	w, path := newWriterForTest(t)
	b := newAuditBridge(w)

	b.EmitAudit(audit.Event{
		Action:   "watcher-block",
		Target:   "demo-skill",
		Details:  "type=skill reason=blocklist",
		Severity: "HIGH",
	})
	_ = w.Close()

	events := readJSONLEvents(t, path)
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	det := events[0].Lifecycle.Details
	if !strings.Contains(det["details"], "reason=blocklist") {
		t.Errorf("details lost: %q", det["details"])
	}
	if events[0].Severity != gatewaylog.SeverityHigh {
		t.Errorf("Severity = %q, want HIGH", events[0].Severity)
	}
}
