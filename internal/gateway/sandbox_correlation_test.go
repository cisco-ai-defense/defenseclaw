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

//go:build !windows

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestSandboxCorrelationIgnoresLoopbackTrust pins that the correlation
// fields a loopback caller may declare (its W3C trace, the policy id and
// the destination app) are never taken from a sandbox. Sandbox traffic
// reaches the ingress from loopback through the OpenShell supervisor, so
// with the loopback gates alone a sandbox chose the trace id of its audit
// rows and the parent of its hook spans, which could be any host trace. The
// chain is the ingress's (trace extraction, request id, correlation) after
// authentication; a host loopback hook keeps what it declares.
func TestSandboxCorrelationIgnoresLoopbackTrust(t *testing.T) {
	const (
		traceID  = "4bf92f3577b34da6a3ce929d0e0e4736"
		parent   = "00-" + traceID + "-00f067aa0ba902b7-01"
		policy   = "dc-policy-7"
		destApp  = "dc-dest-app"
		hookPath = "/api/v1/hermes/hook"
	)
	type seen struct {
		traceID     string
		remote      trace.SpanContext
		envelope    audit.CorrelationEnvelope
		requestSeen bool
	}
	run := func(sandboxed bool) seen {
		var got seen
		var h http.Handler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = seen{
				traceID:     TraceIDFromContext(r.Context()),
				remote:      trace.SpanContextFromContext(r.Context()),
				envelope:    audit.EnvelopeFromContext(r.Context()),
				requestSeen: true,
			}
		})
		h = CorrelationMiddleware(NewAgentRegistry("", ""))(h)
		h = sandboxRequestIDMiddleware(h)
		h = inboundTraceContextMiddleware(h)
		if sandboxed {
			inner := h
			h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := sandboxauth.WithRequest(r.Context(), sandboxTestBinding("hermes"), nil)
				inner.ServeHTTP(w, r.WithContext(ctx))
			})
		}
		req := httptest.NewRequest(http.MethodPost, hookPath, nil).WithContext(context.Background())
		req.RemoteAddr = "127.0.0.1:43210"
		req.Header.Set("traceparent", parent)
		req.Header.Set(PolicyIDHeader, policy)
		req.Header.Set(DestinationAppHeader, destApp)
		h.ServeHTTP(httptest.NewRecorder(), req)
		if !got.requestSeen {
			t.Fatal("the handler was not reached")
		}
		return got
	}

	host := run(false)
	if host.traceID != traceID || host.envelope.TraceID != traceID || !host.remote.IsRemote() ||
		host.remote.TraceID().String() != traceID || host.envelope.PolicyID != policy || host.envelope.DestinationApp != destApp {
		t.Fatalf("host loopback hook = %+v", host)
	}
	sandbox := run(true)
	if sandbox.traceID == traceID || sandbox.envelope.TraceID == traceID || sandbox.remote.IsValid() {
		t.Fatalf("a sandbox chose its trace: %+v", sandbox)
	}
	if sandbox.envelope.PolicyID != "" || sandbox.envelope.DestinationApp != "" {
		t.Fatalf("a sandbox chose its policy id or destination app: %+v", sandbox.envelope)
	}
	if sandbox.envelope.SandboxName != "dc-hermes-app" {
		t.Fatalf("sandbox envelope = %+v", sandbox.envelope)
	}
}
