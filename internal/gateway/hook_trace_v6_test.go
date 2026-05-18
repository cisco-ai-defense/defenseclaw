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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

const (
	wellFormedTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	wellFormedTracestate  = "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE"
)

// hookReq builds an *http.Request whose URL.Path matches a hook
// route so extractIncomingTraceContext considers it in-scope. Any
// other path returns ctx unchanged (route-scope security guard).
func hookReq(t *testing.T, path string, h http.Header) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, nil)
	for k, vv := range h {
		for _, v := range vv {
			r.Header.Add(k, v)
		}
	}
	return r
}

// TestExtractIncomingTraceContext_HookRoute covers the happy path:
// a well-formed traceparent on a hook route produces a context whose
// SpanContext matches the inbound TraceID. Trace propagation is
// always on for hook routes; the rollout signal is whether the agent
// shipped v6 scripts that emit the header at all.
func TestExtractIncomingTraceContext_HookRoute(t *testing.T) {
	h := http.Header{}
	h.Set("traceparent", wellFormedTraceparent)
	h.Set("tracestate", wellFormedTracestate)
	r := hookReq(t, "/api/v1/codex/hook", h)
	got := extractIncomingTraceContext(context.Background(), r)
	sc := trace.SpanFromContext(got).SpanContext()
	if !sc.IsValid() {
		t.Fatalf("expected a valid SpanContext after extraction")
	}
	want := "0af7651916cd43dd8448eb211c80319c"
	if got := sc.TraceID().String(); got != want {
		t.Errorf("TraceID = %q, want %q", got, want)
	}
	if !sc.IsRemote() {
		t.Errorf("expected SpanContext.IsRemote=true (header-sourced span)")
	}
}

// TestExtractIncomingTraceContext_CodexNotifyRoute verifies the
// codex notify-bridge endpoint is also in scope. That route doesn't
// end in /hook so it needs its own allow-list entry.
func TestExtractIncomingTraceContext_CodexNotifyRoute(t *testing.T) {
	h := http.Header{}
	h.Set("traceparent", wellFormedTraceparent)
	r := hookReq(t, "/api/v1/codex/notify", h)
	got := extractIncomingTraceContext(context.Background(), r)
	if !trace.SpanFromContext(got).SpanContext().IsValid() {
		t.Errorf("expected a valid SpanContext for /api/v1/codex/notify")
	}
}

// TestExtractIncomingTraceContext_OutOfScopeRoute is the security
// regression test for H1. A caller hitting any non-hook route MUST
// NOT be able to splice an arbitrary traceparent into the gateway's
// trace tree, even with a well-formed header.
func TestExtractIncomingTraceContext_OutOfScopeRoute(t *testing.T) {
	hostile := []string{
		"/health",
		"/api/v1/scan/code",
		"/otlp/v1/traces",
		"/api/v1/codex/something-else",
		"/api/v1/codex/hookworm",     // suffix match must be exact
		"/api/v1/codex/notify/extra", // path-extension probe
		"/../api/v1/codex/hook",      // traversal probe
	}
	for _, p := range hostile {
		p := p
		t.Run(p, func(t *testing.T) {
			h := http.Header{}
			h.Set("traceparent", wellFormedTraceparent)
			r := hookReq(t, p, h)
			got := extractIncomingTraceContext(context.Background(), r)
			if trace.SpanFromContext(got).SpanContext().IsValid() {
				t.Errorf("route %q accepted traceparent (security regression)", p)
			}
		})
	}
}

// TestExtractIncomingTraceContext_NoHeader verifies the helper does
// not pay for the propagator extract call when the header is absent.
func TestExtractIncomingTraceContext_NoHeader(t *testing.T) {
	r := hookReq(t, "/api/v1/codex/hook", http.Header{})
	got := extractIncomingTraceContext(context.Background(), r)
	if trace.SpanFromContext(got).SpanContext().IsValid() {
		t.Errorf("expected no SpanContext for empty headers")
	}
}

// TestExtractIncomingTraceContext_MalformedHeader covers the
// defensive path: a hostile or truncated traceparent must not
// corrupt the trace tree. The OTel propagator returns the parent
// ctx unchanged when it fails to parse, so a follow-up
// Tracer.Start() will issue a fresh root span — never one
// inheriting from forged values.
func TestExtractIncomingTraceContext_MalformedHeader(t *testing.T) {
	cases := []string{
		"",              // empty: caller handles via no-header branch but defense in depth
		"not-a-tp",      // wrong shape
		"00-zzz-yyy-01", // non-hex
		"00-" + "00000000000000000000000000000000" + "-" + "b7ad6b7169203331" + "-01", // all-zero trace_id
		"00-" + "0af7651916cd43dd8448eb211c80319c" + "-" + "0000000000000000" + "-01", // all-zero span_id
	}
	for _, tp := range cases {
		tp := tp
		t.Run(tp, func(t *testing.T) {
			h := http.Header{}
			h.Set("traceparent", tp)
			r := hookReq(t, "/api/v1/codex/hook", h)
			got := extractIncomingTraceContext(context.Background(), r)
			if span := trace.SpanFromContext(got); span.SpanContext().IsValid() {
				t.Errorf("malformed traceparent %q produced a valid SpanContext", tp)
			}
		})
	}
}
