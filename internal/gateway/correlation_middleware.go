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

// Track 0 foundations — stub owned by Track 7 (Gateway Correlation).
//
// v7 extends request correlation from a single request_id to the
// full correlation quartet that every gatewaylog / audit / OTel
// emission is expected to carry:
//
//   - request_id     : per-HTTP request (already exists — see
//                      requestctx.go)
//   - run_id         : per-sidecar-run (env: DEFENSECLAW_RUN_ID)
//   - session_id     : client-scoped session (header:
//                      X-DefenseClaw-Session-Id)
//   - trace_id       : OTel trace id — propagated via W3C
//                      traceparent header, mirrored into the
//                      Event envelope for cross-sink joins
//
// Plus the three-tier agent identity (AgentID / AgentInstanceID /
// SidecarInstanceID) resolved from AgentRegistry.
//
// Track 0 lands the context-key plumbing + middleware stub so every
// downstream track that reads correlation can depend on a stable
// API. Track 7 wires the middleware into the HTTP chain and starts
// populating fields from inbound headers + OTel context.

import (
	"context"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/trace"
)

// SessionIDHeader is the canonical header used by clients to scope
// a session across multiple requests. Accepting it is optional —
// clients that do not send one get no session_id on their events.
const SessionIDHeader = "X-DefenseClaw-Session-Id"

// maxSessionIDLength bounds client-supplied session identifiers for
// the same reason as maxRequestIDLength — every id is replicated
// across SQLite, JSONL, OTel, and Splunk HEC, so unbounded input is
// a cheap amplification vector.
const maxSessionIDLength = 128

// sessionIDCtxKey / traceIDCtxKey / agentIdentityCtxKey are
// unexported so only this package can write to the slots; readers
// go through the exported helpers below.
type (
	sessionIDCtxKey     struct{}
	traceIDCtxKey       struct{}
	agentIdentityCtxKey struct{}
)

// ContextWithSessionID returns a copy of ctx annotated with id.
// An empty id is a no-op.
func ContextWithSessionID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, sessionIDCtxKey{}, id)
}

// SessionIDFromContext returns the session id attached to ctx, or "".
func SessionIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(sessionIDCtxKey{}).(string)
	return v
}

// ContextWithTraceID returns a copy of ctx annotated with the OTel
// trace id (32-character lowercase hex). Empty is a no-op.
func ContextWithTraceID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, traceIDCtxKey{}, id)
}

// TraceIDFromContext returns the OTel trace id attached to ctx, or "".
// Track 0 stub: Track 7 extends this to auto-populate from the
// active OTel span when the explicit context value is missing.
func TraceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(traceIDCtxKey{}).(string)
	return v
}

// ContextWithAgentIdentity returns a copy of ctx annotated with the
// resolved three-tier agent identity. Passed once at the top of the
// request middleware so downstream handlers do not re-query the
// registry per emission.
func ContextWithAgentIdentity(ctx context.Context, id AgentIdentity) context.Context {
	return context.WithValue(ctx, agentIdentityCtxKey{}, id)
}

// AgentIdentityFromContext returns the agent identity attached to
// ctx, or a zero value. Callers should tolerate the zero value — it
// signals "pre-session traffic, no agent yet".
func AgentIdentityFromContext(ctx context.Context) AgentIdentity {
	if ctx == nil {
		return AgentIdentity{}
	}
	v, _ := ctx.Value(agentIdentityCtxKey{}).(AgentIdentity)
	return v
}

// sessionIDFromHeaders returns the first non-empty session id found
// in the canonical header. Subject to the same sanitiser as the
// request id — length-bounded and stripped of control bytes.
func sessionIDFromHeaders(h http.Header) string {
	v := strings.TrimSpace(h.Get(SessionIDHeader))
	if v == "" {
		return ""
	}
	if len(v) > maxSessionIDLength {
		v = truncateToRuneBoundary(v, maxSessionIDLength)
	}
	if !needsRequestIDClean(v) {
		return v
	}
	return sanitizeClientRequestID(v)
}

// traceIDFromHeaders extracts the W3C traceparent trace id (the
// second of four dash-separated segments). Returns "" when no
// valid traceparent is present. Exported via TraceIDFromContext
// after the middleware runs.
//
// The W3C spec is traceparent: version-traceid-spanid-flags where
// traceid is 32 lowercase hex characters. We do not validate the
// full shape here — Track 7 lands proper traceparent parsing when
// wiring OTel context propagation; Track 0 only needs the happy-
// path shape so downstream schemas have something to match against.
func traceIDFromHeaders(h http.Header) string {
	v := strings.TrimSpace(h.Get("traceparent"))
	if v == "" {
		return ""
	}
	parts := strings.Split(v, "-")
	if len(parts) < 4 {
		return ""
	}
	tid := parts[1]
	if len(tid) != 32 {
		return ""
	}
	return tid
}

// CorrelationMiddleware [Track 0 stub] wraps next with session_id +
// trace_id + agent identity extraction. Must be installed AFTER
// requestIDMiddleware so request_id is already on the context.
//
// Track 7 is the owner that wires this into NewGuardrailProxy and
// NewAPIServer; Track 0 only lands the stub so parallel tracks (9:
// scanner identity, 5: scan results observability) can read from
// AgentIdentityFromContext without stubbing it locally.
//
// NOTE: registry may be nil in tests / local dev — the middleware
// treats nil as "no agent identity" and skips the resolve.
func CorrelationMiddleware(registry *AgentRegistry) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			if sid := sessionIDFromHeaders(r.Header); sid != "" {
				ctx = ContextWithSessionID(ctx, sid)
			}
			inboundAgent := strings.TrimSpace(r.Header.Get(AgentIDHeader))
			if tid := traceIDFromHeaders(r.Header); tid != "" {
				ctx = ContextWithTraceID(ctx, tid)
			} else if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
				ctx = ContextWithTraceID(ctx, span.SpanContext().TraceID().String())
			}
			if registry != nil {
				id := registry.Resolve(ctx, SessionIDFromContext(ctx), inboundAgent)
				ctx = ContextWithAgentIdentity(ctx, id)
				if id.AgentID != "" {
					w.Header().Set(ResponseAgentIDHeader, id.AgentID)
				}
				if id.AgentInstanceID != "" {
					w.Header().Set(AgentInstanceIDHeader, id.AgentInstanceID)
				}
			} else if inboundAgent != "" {
				w.Header().Set(ResponseAgentIDHeader, inboundAgent)
			}

			enrichHTTPSpanFromContext(ctx)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
