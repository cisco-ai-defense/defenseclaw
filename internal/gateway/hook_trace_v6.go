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
	"strings"

	"go.opentelemetry.io/otel/propagation"
)

// hookTraceV6Propagator is the W3C trace-context propagator the
// gateway uses to ingest traceparent / tracestate. Kept as a package
// var so we can mock it in tests (the propagation.TraceContext value
// is stateless and safe to share concurrently).
var hookTraceV6Propagator propagation.TextMapPropagator = propagation.TraceContext{}

// shouldExtractHookTrace reports whether the inbound request belongs
// to a route that participates in agent-side trace propagation.
//
// SECURITY (codeguard-0-logging + codeguard-0-mcp-security):
// Trace extraction is intentionally scoped — accepting traceparent
// on every route would let any caller (including unauthenticated
// /health probes) splice an arbitrary trace into the gateway's
// trace tree. Splice is only legal from a process that we already
// shipped a hook script to, and those scripts only POST to:
//
//   - /api/v1/<connector>/hook  (registered by registerConnectorHookRoutes)
//   - /api/v1/codex/notify       (the codex notify-bridge shim)
//
// The path check below is a strict suffix match against those two
// shapes. Any other route returns false and the gateway mints a
// fresh root span regardless of what the caller sent.
func shouldExtractHookTrace(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	p := r.URL.Path
	if !strings.HasPrefix(p, "/api/v1/") {
		return false
	}
	switch {
	case strings.HasSuffix(p, "/hook"):
		return true
	case p == "/api/v1/codex/notify":
		return true
	}
	return false
}

// extractIncomingTraceContext pulls a W3C trace context out of the
// request headers and returns a context whose parent span is the
// agent-side span. Returns the input ctx unchanged when:
//
//   - the request is on a non-hook route (see shouldExtractHookTrace),
//   - no traceparent header is present, or
//   - the header is empty / malformed (propagator returns unchanged).
//
// SECURITY (codeguard-0-logging + codeguard-0-mcp-security):
//
//   - Scope is enforced by shouldExtractHookTrace: only the two
//     known agent→gateway POST routes participate. Health probes,
//     OTLP ingest, REST APIs, and the OTLP-HTTP receiver all see
//     a fresh root span.
//   - The propagator's parsing is strict per RFC 9242; an
//     untrusted traceparent string cannot crash the gateway nor
//     forge an arbitrary span ID into the local trace tree because
//     a child span issued under this context still gets a fresh
//     local span id.
//   - tracestate is bounded to 512 bytes by the shell-side
//     validator before it is sent; the propagator independently
//     enforces the W3C upper bound.
//   - Validation of traceparent shape happens inside the OTel
//     propagator (no custom regex). When parsing fails the
//     propagator returns the parent context unchanged, so an
//     invalid header degrades to "no remote parent" — never to a
//     forged span.
//
// The helper does NOT log the inbound trace ids: the existing
// CorrelationMiddleware already records trace_id from the same
// header, and double-logging risks operator confusion.
func extractIncomingTraceContext(ctx context.Context, r *http.Request) context.Context {
	if !shouldExtractHookTrace(r) {
		return ctx
	}
	if r.Header == nil {
		return ctx
	}
	if strings.TrimSpace(r.Header.Get("traceparent")) == "" {
		return ctx
	}
	return hookTraceV6Propagator.Extract(ctx, propagation.HeaderCarrier(r.Header))
}
