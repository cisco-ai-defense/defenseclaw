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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// captureEmitter records every audit.Event it receives. Guarded by a
// mutex because EmitAudit runs on the Logger hot path and concurrent
// Log* callers must not race on the slice.
type captureEmitter struct {
	mu     sync.Mutex
	events []Event
}

func (c *captureEmitter) EmitAudit(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureEmitter) EmitGatewayEvent(_ gatewaylog.Event) {}

func (c *captureEmitter) snapshot() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Event, len(c.events))
	copy(out, c.events)
	return out
}

func newLoggerForTest(t *testing.T) *Logger {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return NewLogger(store)
}

func TestLoggerStructuredEmitter_ReceivesLogAction(t *testing.T) {
	l := newLoggerForTest(t)
	cap := &captureEmitter{}
	l.SetStructuredEmitter(cap)

	if err := l.LogAction("sidecar-start", "", "booting"); err != nil {
		t.Fatalf("LogAction: %v", err)
	}
	events := cap.snapshot()
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Action != "sidecar-start" {
		t.Errorf("Action = %q, want sidecar-start", events[0].Action)
	}
	if events[0].ID == "" {
		t.Errorf("ID not populated — emitter received pre-persistence event")
	}
	if events[0].Timestamp.IsZero() {
		t.Errorf("Timestamp not populated")
	}
}

func TestLoggerStructuredEmitter_ReceivesLogEvent(t *testing.T) {
	l := newLoggerForTest(t)
	cap := &captureEmitter{}
	l.SetStructuredEmitter(cap)

	if err := l.LogEvent(Event{
		Action:   "gateway-ready",
		Target:   "guardrail-proxy",
		Actor:    "defenseclaw",
		Severity: "INFO",
	}); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}
	events := cap.snapshot()
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Action != "gateway-ready" {
		t.Errorf("Action = %q, want gateway-ready", events[0].Action)
	}
}

func TestLoggerStructuredEmitter_ReceivesLogScan(t *testing.T) {
	l := newLoggerForTest(t)
	cap := &captureEmitter{}
	l.SetStructuredEmitter(cap)

	result := &scanner.ScanResult{
		Scanner:   "skill-scanner",
		Target:    "demo-skill",
		Timestamp: time.Now().UTC(),
		Duration:  42 * time.Millisecond,
	}
	if err := l.LogScan(result); err != nil {
		t.Fatalf("LogScan: %v", err)
	}
	events := cap.snapshot()
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Action != "scan" {
		t.Errorf("Action = %q, want scan", events[0].Action)
	}
	if events[0].Target != "demo-skill" {
		t.Errorf("Target = %q, want demo-skill", events[0].Target)
	}
}

func TestLoggerStructuredEmitter_DetachOnNil(t *testing.T) {
	l := newLoggerForTest(t)
	cap := &captureEmitter{}
	l.SetStructuredEmitter(cap)
	l.SetStructuredEmitter(nil)

	if err := l.LogAction("sidecar-stop", "", ""); err != nil {
		t.Fatalf("LogAction: %v", err)
	}
	if got := len(cap.snapshot()); got != 0 {
		t.Fatalf("emitter still received events after detach: got %d", got)
	}
}

func TestLoggerStructuredEmitter_RedactionPreserved(t *testing.T) {
	l := newLoggerForTest(t)
	cap := &captureEmitter{}
	l.SetStructuredEmitter(cap)

	// SSN in details — sanitizeEvent must redact before the emitter sees it.
	if err := l.LogAction("skill-block", "demo", "reason=contains SSN 123-45-6789"); err != nil {
		t.Fatalf("LogAction: %v", err)
	}
	events := cap.snapshot()
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if got := events[0].Details; containsLiteralSSN(got) {
		t.Errorf("emitter received unsanitized Details: %q", got)
	}
}

// containsLiteralSSN returns true only when a raw 9-digit SSN pattern
// slipped through redaction. Helper rather than inline regex so the
// test stays readable.
func containsLiteralSSN(s string) bool {
	runes := []rune(s)
	for i := 0; i+11 <= len(runes); i++ {
		if isDigit(runes[i]) && isDigit(runes[i+1]) && isDigit(runes[i+2]) &&
			runes[i+3] == '-' &&
			isDigit(runes[i+4]) && isDigit(runes[i+5]) &&
			runes[i+6] == '-' &&
			isDigit(runes[i+7]) && isDigit(runes[i+8]) && isDigit(runes[i+9]) &&
			isDigit(runes[i+10]) {
			return true
		}
	}
	return false
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// TestLogger_ConcurrentSetAndLogRaceFree is the L1 regression guard.
// Before the mutex-protected setters landed, a goroutine calling
// LogEvent/LogAction while the shutdown path flipped
// SetStructuredEmitter(nil) or SetSinks(nil) had a data race on
// interface-typed fields — interface writes are two-word stores and
// tearing produced use-after-free crashes.
//
// The test hammers the Logger with concurrent LogEvent calls while
// another goroutine toggles every setter in a tight loop. Running
// with `-race` must stay silent.
func TestLogger_ConcurrentSetAndLogRaceFree(t *testing.T) {
	l := newLoggerForTest(t)

	// We don't care what the emitter does — it just has to be
	// something swappable under the lock.
	emitter1 := &captureEmitter{}
	emitter2 := &captureEmitter{}

	const workers = 8
	const perWorker = 128
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				_ = l.LogEvent(Event{
					Action:   "race-test",
					Target:   "t",
					Actor:    "a",
					Severity: "INFO",
				})
			}
		}(i)
	}

	// Setter thrasher: toggles every field under test until the
	// workers finish. Close(done) signals it to stop.
	setterWG := sync.WaitGroup{}
	setterWG.Add(1)
	go func() {
		defer setterWG.Done()
		toggle := 0
		for {
			select {
			case <-done:
				return
			default:
			}
			switch toggle % 4 {
			case 0:
				l.SetStructuredEmitter(emitter1)
			case 1:
				l.SetStructuredEmitter(emitter2)
			case 2:
				l.SetStructuredEmitter(nil)
			case 3:
				l.SetSinks(nil)
			}
			toggle++
		}
	}()

	wg.Wait()
	close(done)
	setterWG.Wait()

	// Final sanity: the logger is still usable after the thrashing.
	// A goroutine mid-SetStructuredEmitter can't have poisoned state.
	l.SetStructuredEmitter(nil)
	if err := l.LogEvent(Event{Action: "post-race", Severity: "INFO"}); err != nil {
		t.Fatalf("post-race LogEvent: %v", err)
	}
}
