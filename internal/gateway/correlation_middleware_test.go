// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestContextHelpers_RoundTrip pins the symmetric read/write helpers
// so the three independent keyed slots (session/trace/identity) do
// not accidentally alias each other in future refactors.
func TestContextHelpers_RoundTrip(t *testing.T) {
	ctx := context.Background()

	ctx = ContextWithSessionID(ctx, "sess-1")
	ctx = ContextWithTraceID(ctx, "abcdef")
	id := AgentIdentity{AgentID: "a", SidecarInstanceID: "sc"}
	ctx = ContextWithAgentIdentity(ctx, id)

	if got := SessionIDFromContext(ctx); got != "sess-1" {
		t.Errorf("SessionIDFromContext=%q, want sess-1", got)
	}
	if got := TraceIDFromContext(ctx); got != "abcdef" {
		t.Errorf("TraceIDFromContext=%q, want abcdef", got)
	}
	if got := AgentIdentityFromContext(ctx); got != id {
		t.Errorf("AgentIdentityFromContext=%+v, want %+v", got, id)
	}
}

// TestContextHelpers_NilSafe guards panic paths for tests that pass
// nil contexts (we explicitly document nil is tolerated).
func TestContextHelpers_NilSafe(t *testing.T) {
	if got := SessionIDFromContext(nil); got != "" {
		t.Errorf("nil ctx SessionID = %q", got)
	}
	if got := TraceIDFromContext(nil); got != "" {
		t.Errorf("nil ctx TraceID = %q", got)
	}
	if got := AgentIdentityFromContext(nil); got != (AgentIdentity{}) {
		t.Errorf("nil ctx AgentIdentity = %+v", got)
	}
}

// TestContextHelpers_EmptyValueIsNoOp ensures we do not burn a
// context allocation for zero values.
func TestContextHelpers_EmptyValueIsNoOp(t *testing.T) {
	base := context.Background()
	if got := ContextWithSessionID(base, ""); got != base {
		t.Error("empty session id allocated a new ctx")
	}
	if got := ContextWithTraceID(base, ""); got != base {
		t.Error("empty trace id allocated a new ctx")
	}
}

// TestTraceIDFromHeaders_Parses_W3C covers the happy path of the
// W3C traceparent extractor.
func TestTraceIDFromHeaders_Parses_W3C(t *testing.T) {
	cases := []struct {
		name string
		hdr  string
		want string
	}{
		{
			name: "well-formed traceparent",
			hdr:  "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			want: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
		{
			name: "empty",
			hdr:  "",
			want: "",
		},
		{
			name: "too few segments",
			hdr:  "00-only-two",
			want: "",
		},
		{
			name: "wrong trace id length",
			hdr:  "00-notahex-spanid-01",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.hdr != "" {
				h.Set("traceparent", tc.hdr)
			}
			if got := traceIDFromHeaders(h); got != tc.want {
				t.Errorf("traceIDFromHeaders=%q, want %q", got, tc.want)
			}
		})
	}
}

// TestSessionIDFromHeaders_Bounded checks the length + control-byte
// stripping; a hostile client sending a multi-megabyte header must
// be truncated before it reaches SQLite/Splunk.
func TestSessionIDFromHeaders_Bounded(t *testing.T) {
	huge := strings.Repeat("A", maxSessionIDLength*2)
	h := http.Header{}
	h.Set(SessionIDHeader, huge)
	got := sessionIDFromHeaders(h)
	if len(got) > maxSessionIDLength {
		t.Errorf("session id not bounded: len=%d cap=%d", len(got), maxSessionIDLength)
	}

	h2 := http.Header{}
	h2.Set(SessionIDHeader, "safe\x00id")
	got2 := sessionIDFromHeaders(h2)
	if strings.ContainsAny(got2, "\x00\n\r") {
		t.Errorf("control bytes leaked into session id: %q", got2)
	}
}

// TestCorrelationMiddleware_PopulatesContext wires the middleware to
// an end-to-end HTTP test and asserts session/trace/agent identity
// land in the downstream context.
func TestCorrelationMiddleware_PopulatesContext(t *testing.T) {
	reg := NewAgentRegistry("agent-ci", "CI Agent")
	mw := CorrelationMiddleware(reg)

	var (
		gotSession, gotTrace string
		gotIdentity          AgentIdentity
	)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSession = SessionIDFromContext(r.Context())
		gotTrace = TraceIDFromContext(r.Context())
		gotIdentity = AgentIdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(SessionIDHeader, "sess-abc")
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if gotSession != "sess-abc" {
		t.Errorf("session=%q, want sess-abc", gotSession)
	}
	if gotTrace != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace=%q, want 4bf9...4736", gotTrace)
	}
	if gotIdentity.AgentID != "agent-ci" {
		t.Errorf("agent_id=%q, want agent-ci", gotIdentity.AgentID)
	}
	if gotIdentity.SidecarInstanceID != reg.SidecarInstanceID() {
		t.Errorf("sidecar instance mismatch: mw=%q reg=%q",
			gotIdentity.SidecarInstanceID, reg.SidecarInstanceID())
	}
	if gotIdentity.AgentInstanceID == "" {
		t.Error("agent_instance_id empty; want session-scoped uuid")
	}
}

// TestCorrelationMiddleware_NilRegistryTolerated makes the
// middleware safe to install in degraded modes / unit harnesses.
func TestCorrelationMiddleware_NilRegistryTolerated(t *testing.T) {
	mw := CorrelationMiddleware(nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := AgentIdentityFromContext(r.Context()); got != (AgentIdentity{}) {
			t.Errorf("expected zero AgentIdentity with nil registry, got %+v", got)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)
}
