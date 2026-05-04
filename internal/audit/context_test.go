// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
)

// TestEnvelopeFromContext_RoundTrip pins the happy path: an envelope
// stashed by the gateway middleware comes back intact for any
// downstream audit caller in the same request scope.
func TestEnvelopeFromContext_RoundTrip(t *testing.T) {
	in := CorrelationEnvelope{
		RunID:           "run-rt",
		TraceID:         "trace-rt",
		RequestID:       "req-rt",
		SessionID:       "sess-rt",
		AgentID:         "agent-rt",
		AgentName:       "openclaw",
		AgentInstanceID: "inst-rt",
		PolicyID:        "policy-rt",
	}
	ctx := ContextWithEnvelope(context.Background(), in)
	got := EnvelopeFromContext(ctx)
	if got != in {
		t.Fatalf("envelope mismatch:\n got  %+v\n want %+v", got, in)
	}
}

// TestEnvelopeFromContext_NilCtxReturnsZero pins the nil-safety
// contract: LogEventCtx must never panic when called from a test
// harness or a background worker that doesn't carry a request ctx.
func TestEnvelopeFromContext_NilCtxReturnsZero(t *testing.T) {
	var nilCtx context.Context
	got := EnvelopeFromContext(nilCtx)
	if got != (CorrelationEnvelope{}) {
		t.Fatalf("want zero envelope from nil ctx, got %+v", got)
	}
}

// TestLogEventCtx_FillsFromEnvelope verifies the core v7 contract:
// an audit.Event missing correlation fields gets them auto-filled
// from the ctx envelope before landing in the store. This is what
// keeps every audit row joinable with the matching gateway.jsonl
// row without each call site plumbing seven strings manually.
func TestLogEventCtx_FillsFromEnvelope(t *testing.T) {
	l := newTestLogger(t)
	env := CorrelationEnvelope{
		RunID:           "run-ctx",
		TraceID:         "trace-ctx",
		RequestID:       "req-ctx",
		SessionID:       "sess-ctx",
		AgentID:         "agent-ctx",
		AgentName:       "ctx-agent",
		AgentInstanceID: "inst-ctx",
		PolicyID:        "policy-ctx",
		DestinationApp:  "openai",
		ToolName:        "web_search",
		ToolID:          "tool-1",
	}
	ctx := ContextWithEnvelope(context.Background(), env)

	// Caller provides only action + target; the ctx should fill
	// the rest. This is the "handler wrote one line" ergonomic
	// that the correlation middleware enables.
	if err := l.LogEventCtx(ctx, Event{
		Action: "test.ctx",
		Target: "unit",
	}); err != nil {
		t.Fatalf("LogEventCtx: %v", err)
	}

	// Read back the persisted row and assert the envelope landed.
	rows, err := l.store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no rows persisted")
	}
	got := rows[0]
	if got.RunID != env.RunID {
		t.Errorf("RunID=%q want %q", got.RunID, env.RunID)
	}
	if got.TraceID != env.TraceID {
		t.Errorf("TraceID=%q want %q", got.TraceID, env.TraceID)
	}
	if got.RequestID != env.RequestID {
		t.Errorf("RequestID=%q want %q", got.RequestID, env.RequestID)
	}
	if got.SessionID != env.SessionID {
		t.Errorf("SessionID=%q want %q", got.SessionID, env.SessionID)
	}
	if got.AgentID != env.AgentID {
		t.Errorf("AgentID=%q want %q", got.AgentID, env.AgentID)
	}
	if got.AgentName != env.AgentName {
		t.Errorf("AgentName=%q want %q", got.AgentName, env.AgentName)
	}
	if got.AgentInstanceID != env.AgentInstanceID {
		t.Errorf("AgentInstanceID=%q want %q", got.AgentInstanceID, env.AgentInstanceID)
	}
	if got.PolicyID != env.PolicyID {
		t.Errorf("PolicyID=%q want %q", got.PolicyID, env.PolicyID)
	}
	if got.DestinationApp != env.DestinationApp {
		t.Errorf("DestinationApp=%q want %q", got.DestinationApp, env.DestinationApp)
	}
	if got.ToolName != env.ToolName {
		t.Errorf("ToolName=%q want %q", got.ToolName, env.ToolName)
	}
	if got.ToolID != env.ToolID {
		t.Errorf("ToolID=%q want %q", got.ToolID, env.ToolID)
	}
}

// TestLogEventCtx_CallerOverridesEnvelope pins the "caller intent
// wins" contract: when a call site already knows the envelope value
// for a specific field (e.g. a scanner callback that uses the agent
// pinned by the scan target, not the request), the ctx MUST NOT
// overwrite it. Matches the pattern used by store.LogEvent for
// provenance stamping.
func TestLogEventCtx_CallerOverridesEnvelope(t *testing.T) {
	l := newTestLogger(t)
	ctx := ContextWithEnvelope(context.Background(), CorrelationEnvelope{
		RunID:   "run-from-ctx",
		AgentID: "agent-from-ctx",
	})
	if err := l.LogEventCtx(ctx, Event{
		Action:  "test.pin",
		Target:  "unit",
		AgentID: "agent-pinned-by-caller",
	}); err != nil {
		t.Fatalf("LogEventCtx: %v", err)
	}
	rows, err := l.store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	got := rows[0]
	if got.AgentID != "agent-pinned-by-caller" {
		t.Errorf("AgentID=%q want caller pin", got.AgentID)
	}
	if got.RunID != "run-from-ctx" {
		t.Errorf("RunID=%q want fill from ctx", got.RunID)
	}
}
