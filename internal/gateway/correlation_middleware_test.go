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

	"github.com/defenseclaw/defenseclaw/internal/audit"
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

// TestCorrelationMiddleware_StampsAuditEnvelope closes the v7 loop:
// the middleware snapshots the resolved correlation + agent identity
// into an audit.CorrelationEnvelope so any downstream call to
// audit.Logger.LogEventCtx auto-fills all seven fields without the
// handler plumbing them through manually. Regressing this means
// every audit row in a request scope loses its join keys.
func TestCorrelationMiddleware_StampsAuditEnvelope(t *testing.T) {
	reg := NewAgentRegistry("agent-env", "Envelope Agent")
	mw := CorrelationMiddleware(reg)

	t.Setenv("DEFENSECLAW_RUN_ID", "run-env-1")

	var env audit.CorrelationEnvelope
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env = audit.EnvelopeFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(SessionIDHeader, "sess-env")
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if env.RunID != "run-env-1" {
		t.Errorf("RunID=%q want run-env-1", env.RunID)
	}
	if env.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("TraceID=%q want 4bf9...4736", env.TraceID)
	}
	if env.SessionID != "sess-env" {
		t.Errorf("SessionID=%q want sess-env", env.SessionID)
	}
	if env.AgentID != "agent-env" {
		t.Errorf("AgentID=%q want agent-env", env.AgentID)
	}
	if env.AgentInstanceID == "" {
		t.Error("AgentInstanceID empty; want session-scoped uuid")
	}
}

// TestCorrelationMiddleware_StampsPolicyAndDestination pins the v7
// extension where the middleware reads X-DefenseClaw-Policy-Id and
// X-DefenseClaw-Destination-App off the request headers and threads
// them onto the audit envelope. Before this extension every runtime
// event in SQLite had policy_id and destination_app NULL because the
// middleware stopped at session/trace/agent — the correlation
// envelope silently dropped these fields on the floor. Regressing
// this means guardrail verdicts lose their policy attribution and
// destination analytics break.
func TestCorrelationMiddleware_StampsPolicyAndDestination(t *testing.T) {
	reg := NewAgentRegistry("agent-env", "Envelope Agent")
	mw := CorrelationMiddleware(reg)

	var env audit.CorrelationEnvelope
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env = audit.EnvelopeFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(PolicyIDHeader, "strict-prod")
	req.Header.Set(DestinationAppHeader, "openclaw-ide")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if env.PolicyID != "strict-prod" {
		t.Errorf("PolicyID=%q want strict-prod", env.PolicyID)
	}
	if env.DestinationApp != "openclaw-ide" {
		t.Errorf("DestinationApp=%q want openclaw-ide", env.DestinationApp)
	}
}

// TestCorrelationMiddleware_BoundsPolicyAndDestination guards the
// length cap / control-byte strip on policy/destination headers so
// a hostile client cannot blow up SQLite rows or pollute sink fan-out
// with multi-MB header values.
func TestCorrelationMiddleware_BoundsPolicyAndDestination(t *testing.T) {
	hugePolicy := strings.Repeat("P", maxPolicyIDLength*2)
	hugeDest := strings.Repeat("D", maxDestinationAppLength*2)

	h := http.Header{}
	h.Set(PolicyIDHeader, hugePolicy+"\x00newline")
	h.Set(DestinationAppHeader, hugeDest+"\n\rnull")

	if got := policyIDFromHeaders(h); len(got) > maxPolicyIDLength {
		t.Errorf("policy id not bounded: len=%d cap=%d", len(got), maxPolicyIDLength)
	} else if strings.ContainsAny(got, "\x00\n\r") {
		t.Errorf("control bytes leaked into policy id: %q", got)
	}
	if got := destinationAppFromHeaders(h); len(got) > maxDestinationAppLength {
		t.Errorf("dest not bounded: len=%d cap=%d", len(got), maxDestinationAppLength)
	} else if strings.ContainsAny(got, "\x00\n\r") {
		t.Errorf("control bytes leaked into dest: %q", got)
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
