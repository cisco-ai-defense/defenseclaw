// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sinks

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSink is a thread-safe in-memory Sink used to exercise the Manager
// without touching the network. We deliberately mimic the contract of the
// real sinks (Forward may buffer, Flush drains, Close releases) so the
// Manager's sequencing is validated end to end.
type fakeSink struct {
	name, kind string

	mu       sync.Mutex
	received []Event
	flushes  int
	closed   bool

	filter SinkFilter

	forwardErr atomic.Value // error
	flushErr   atomic.Value // error
}

func newFakeSink(name string) *fakeSink {
	return &fakeSink{name: name, kind: "fake"}
}

func (s *fakeSink) Name() string { return s.name }
func (s *fakeSink) Kind() string { return s.kind }

func (s *fakeSink) Forward(_ context.Context, e Event) error {
	if err, ok := s.forwardErr.Load().(error); ok && err != nil {
		return err
	}
	if !s.filter.Matches(e) {
		return nil
	}
	s.mu.Lock()
	s.received = append(s.received, e)
	s.mu.Unlock()
	return nil
}

func (s *fakeSink) Flush(_ context.Context) error {
	if err, ok := s.flushErr.Load().(error); ok && err != nil {
		return err
	}
	s.mu.Lock()
	s.flushes++
	s.mu.Unlock()
	return nil
}

func (s *fakeSink) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *fakeSink) snapshot() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.received))
	copy(out, s.received)
	return out
}

func TestSeverityRank_MapsAndFallsBack(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", severityInfo},
		{"INFO", severityInfo},
		{"info", severityInfo},
		{"NONE", severityInfo},
		{"low", severityLow},
		{"MED", severityMedium},
		{"medium", severityMedium},
		{"HIGH", severityHigh},
		{"CRITICAL", severityCritical},
		{"bogus", severityInfo}, // unknown must not drop events
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := severityRank(tt.in); got != tt.want {
				t.Fatalf("severityRank(%q)=%d want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestSinkFilter_Matches(t *testing.T) {
	tests := []struct {
		name  string
		ev    Event
		filt  SinkFilter
		match bool
	}{
		{"empty filter matches anything",
			Event{Action: "scan-complete", Severity: "INFO"}, SinkFilter{}, true},
		{"min severity blocks below threshold",
			Event{Severity: "LOW"}, SinkFilter{MinSeverity: "HIGH"}, false},
		{"min severity allows equal",
			Event{Severity: "HIGH"}, SinkFilter{MinSeverity: "HIGH"}, true},
		{"min severity allows above",
			Event{Severity: "CRITICAL"}, SinkFilter{MinSeverity: "HIGH"}, true},
		{"action allowlist matches",
			Event{Action: "guardrail-verdict", Severity: "INFO"},
			SinkFilter{Actions: []string{"guardrail-verdict", "sidecar-start"}}, true},
		{"action allowlist rejects unlisted",
			Event{Action: "heartbeat", Severity: "INFO"},
			SinkFilter{Actions: []string{"guardrail-verdict"}}, false},
		{"unknown severity treated as info (rank 1), blocks when min=HIGH",
			Event{Severity: "UNKNOWN"}, SinkFilter{MinSeverity: "HIGH"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filt.Matches(tt.ev); got != tt.match {
				t.Fatalf("Matches=%v want %v", got, tt.match)
			}
		})
	}
}

func TestManager_ZeroValueIsNoop(t *testing.T) {
	var m *Manager
	if errs := m.Forward(context.Background(), Event{}); len(errs) > 0 {
		t.Fatalf("nil Manager.Forward err=%v, want nil", errs)
	}
	if n := m.Len(); n != 0 {
		t.Fatalf("nil Manager.Len=%d", n)
	}
	if err := m.FlushAll(context.Background()); err != nil {
		t.Fatalf("nil Manager.FlushAll err=%v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("nil Manager.Close err=%v", err)
	}
}

func TestManager_RegisterAndFanout(t *testing.T) {
	m := NewManager()
	a := newFakeSink("a")
	b := newFakeSink("b")
	m.Register(a)
	m.Register(b)
	m.Register(nil) // must be ignored, not panic
	if got := m.Len(); got != 2 {
		t.Fatalf("Len=%d want 2 (nil must be skipped)", got)
	}

	ev := Event{ID: "e1", Action: "scan-complete", Severity: "HIGH",
		Timestamp: time.Unix(1700000000, 0)}
	if errs := m.Forward(context.Background(), ev); len(errs) > 0 {
		t.Fatalf("Forward err=%v", errs)
	}

	if got := a.snapshot(); len(got) != 1 || got[0].ID != "e1" {
		t.Fatalf("sink a received=%#v", got)
	}
	if got := b.snapshot(); len(got) != 1 || got[0].ID != "e1" {
		t.Fatalf("sink b received=%#v", got)
	}
}

func TestManager_Forward_AggregatesErrorsButKeepsDelivering(t *testing.T) {
	// Redirect stderr so warning prints don't pollute test output; the
	// Manager is expected to log + aggregate errors while still delivering
	// to healthy sinks.
	m := NewManager()
	devnull, _ := os.Open(os.DevNull)
	m.stderr = devnull
	defer devnull.Close()

	healthy := newFakeSink("healthy")
	broken := newFakeSink("broken")
	broken.forwardErr.Store(errors.New("downstream 500"))

	m.Register(broken)
	m.Register(healthy)

	errs := m.Forward(context.Background(), Event{ID: "e", Action: "scan"})
	if len(errs) == 0 {
		t.Fatalf("expected aggregated error, got nil")
	}
	var agg string
	for n, e := range errs {
		agg += n + ": " + e.Error()
	}
	if !strings.Contains(agg, "broken") ||
		!strings.Contains(agg, "downstream 500") {
		t.Fatalf("error missing sink context: %v", agg)
	}
	if got := len(healthy.snapshot()); got != 1 {
		t.Fatalf("healthy sink not delivered-to despite broken peer: %d", got)
	}
}

func TestManager_ImmediateFlushActions(t *testing.T) {
	m := NewManager()
	s := newFakeSink("s")
	m.Register(s)

	// `sidecar-start` is in the default immediate-flush list — Manager
	// fires a background FlushAll. We poll the sink briefly instead of
	// relying on a fixed sleep.
	if errs := m.Forward(context.Background(),
		Event{Action: "sidecar-start", Severity: "INFO"}); len(errs) > 0 {
		t.Fatalf("Forward err=%v", errs)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := s.flushes
		s.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected async flush after immediate-flush action")
}

func TestManager_SetImmediateFlushActions_EmptyRestoresDefaults(t *testing.T) {
	m := NewManager()
	m.SetImmediateFlushActions([]string{"custom-event"})
	if _, ok := m.flushImmediateActions["custom-event"]; !ok {
		t.Fatal("custom action not installed")
	}
	m.SetImmediateFlushActions(nil)
	// Defaults must be reinstalled — check one canonical entry.
	if _, ok := m.flushImmediateActions["sidecar-start"]; !ok {
		t.Fatal("defaults not restored after empty SetImmediateFlushActions")
	}
}

func TestManager_FlushAll_AggregatesErrors(t *testing.T) {
	m := NewManager()
	devnull, _ := os.Open(os.DevNull)
	m.stderr = devnull
	defer devnull.Close()

	good := newFakeSink("good")
	bad := newFakeSink("bad")
	bad.flushErr.Store(errors.New("boom"))
	m.Register(good)
	m.Register(bad)

	err := m.FlushAll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("expected aggregated flush error, got %v", err)
	}
	good.mu.Lock()
	if good.flushes != 1 {
		t.Fatalf("good sink flushed=%d want 1", good.flushes)
	}
	good.mu.Unlock()
}

func TestManager_Close_FlushesAndCloses_AndMakesForwardNoop(t *testing.T) {
	m := NewManager()
	s := newFakeSink("s")
	m.Register(s)

	if err := m.Close(); err != nil {
		t.Fatalf("Close err=%v", err)
	}
	s.mu.Lock()
	if !s.closed {
		t.Fatal("Close did not close underlying sink")
	}
	if s.flushes != 1 {
		t.Fatalf("Close did not flush (flushes=%d)", s.flushes)
	}
	s.mu.Unlock()

	// Post-Close: Forward must be a no-op because Close clears the sink
	// list. Nothing should be delivered.
	if errs := m.Forward(context.Background(), Event{ID: "post-close"}); len(errs) > 0 {
		t.Fatalf("Forward after Close err=%v (must be noop)", errs)
	}
	if got := len(s.snapshot()); got != 0 {
		t.Fatalf("sink received %d events after Close, want 0", got)
	}
}

// panicSink deliberately panics inside Forward so we can verify the
// Manager's recover() guard. Without the guard, a panicking third-
// party sink would unwind through audit.Logger into the guardrail
// hot path.
type panicSink struct {
	name string
}

func (p *panicSink) Name() string                             { return p.name }
func (p *panicSink) Kind() string                             { return "panic" }
func (p *panicSink) Forward(_ context.Context, _ Event) error { panic("sink boom") }
func (p *panicSink) Flush(_ context.Context) error            { return nil }
func (p *panicSink) Close() error                             { return nil }

func TestManager_Forward_RecoversFromSinkPanic(t *testing.T) {
	m := NewManager()
	devnull, _ := os.Open(os.DevNull)
	m.stderr = devnull
	defer devnull.Close()

	healthy := newFakeSink("healthy")
	m.Register(&panicSink{name: "explosive"})
	m.Register(healthy)

	// A panicking sink must not unwind into the caller; the panic
	// is converted into a forward error and the healthy peer still
	// receives the event.
	errs := m.Forward(context.Background(), Event{ID: "e", Action: "scan"})
	if len(errs) == 0 {
		t.Fatalf("expected aggregated error from panicking sink")
	}
	var agg string
	for n, e := range errs {
		agg += n + ": " + e.Error()
	}
	if !strings.Contains(agg, "panic") {
		t.Fatalf("panic not surfaced in aggregated error: %v", agg)
	}
	if got := len(healthy.snapshot()); got != 1 {
		t.Fatalf("healthy peer starved by panicking sink: got %d events", got)
	}
}

func TestManager_Forward_CoalescesImmediateFlushes(t *testing.T) {
	// Burst many immediate-flush actions and verify we do NOT spawn
	// one goroutine per call — the single-flight atomic should
	// collapse concurrent immediate flushes into at most one
	// in-flight flush at a time. This is the regression guard for
	// the "guardrail-verdict goroutine explosion" bug.
	m := NewManager()
	devnull, _ := os.Open(os.DevNull)
	m.stderr = devnull
	defer devnull.Close()

	s := newFakeSink("s")
	m.Register(s)

	for i := 0; i < 1000; i++ {
		_ = m.Forward(context.Background(),
			Event{Action: "guardrail-verdict", Severity: "HIGH"})
	}

	// Let any scheduled flush fan-out drain.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := s.flushes
		s.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.mu.Lock()
	flushes := s.flushes
	s.mu.Unlock()
	// The exact number is timing-dependent (CompareAndSwap lets
	// subsequent bursts re-fire once the goroutine completes) but
	// must be *far* below the 1000 Forward calls.
	if flushes == 0 {
		t.Fatal("coalesced flush never fired")
	}
	if flushes >= 100 {
		t.Fatalf("flush coalescing failed: 1000 Forwards produced %d flushes", flushes)
	}
}
