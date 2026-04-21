// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	auditsinks "github.com/defenseclaw/defenseclaw/internal/audit/sinks"
)

type captureAuditSink struct {
	mu     sync.Mutex
	events []auditsinks.Event
}

func (s *captureAuditSink) Name() string { return "capture" }
func (s *captureAuditSink) Kind() string { return "capture" }

func (s *captureAuditSink) Forward(_ context.Context, e auditsinks.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

func (s *captureAuditSink) Flush(context.Context) error { return nil }
func (s *captureAuditSink) Close() error                { return nil }

func (s *captureAuditSink) snapshot() []auditsinks.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auditsinks.Event, len(s.events))
	copy(out, s.events)
	return out
}

func installAuditCaptureSink(logger *audit.Logger) *captureAuditSink {
	cap := &captureAuditSink{}
	mgr := auditsinks.NewManager()
	mgr.Register(cap)
	logger.SetSinks(mgr)
	return cap
}

func TestPersistAuditEvent_UsesLoggerPipeline(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := audit.NewLogger(store)
	capture := installAuditCaptureSink(logger)

	err = persistAuditEvent(logger, store, audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    "audit-api",
		Target:    "demo-target",
		Details:   "email=user@example.com",
		Severity:  "HIGH",
		TraceID:   "trace-123",
	})
	if err != nil {
		t.Fatalf("persistAuditEvent: %v", err)
	}
	logger.Close()

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("ListEvents rows=%d want 1", len(events))
	}
	if got := events[0].TraceID; got != "trace-123" {
		t.Fatalf("store TraceID=%q want %q", got, "trace-123")
	}
	if strings.Contains(events[0].Details, "user@example.com") {
		t.Fatalf("store details leaked raw email: %q", events[0].Details)
	}

	forwarded := capture.snapshot()
	if len(forwarded) != 1 {
		t.Fatalf("forwarded rows=%d want 1", len(forwarded))
	}
	if got := forwarded[0].TraceID; got != "trace-123" {
		t.Fatalf("sink TraceID=%q want %q", got, "trace-123")
	}
	if strings.Contains(forwarded[0].Details, "user@example.com") {
		t.Fatalf("sink details leaked raw email: %q", forwarded[0].Details)
	}
}
