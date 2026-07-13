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

// Request correlation plumbing. Every gatewaylog / audit / OTel
// emission carries the full correlation quartet:
//
//   - request_id     : per-HTTP request (assigned by
//                      requestIDMiddleware in requestctx.go)
//   - run_id         : per-sidecar-run (env: DEFENSECLAW_RUN_ID,
//                      mirrored via gatewaylog.ProcessRunID())
//   - session_id     : client-scoped session (header:
//                      X-DefenseClaw-Session-Id)
//   - trace_id       : OTel trace id — propagated via W3C
//                      traceparent header, mirrored into the
//                      Event envelope for cross-sink joins
//
// Plus the three-tier agent identity (AgentID / AgentInstanceID /
// SidecarInstanceID) resolved from AgentRegistry on the request
// path.
//
// The context-key plumbing + middleware live here so every emission
// site (audit logger, OTel exporter, structured log writer) reads
// from a single stable API instead of re-parsing headers per call.

import (
	"context"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// currentProcessRunID snapshots the per-process run id once per
// request. Prefers the atomic slot installed at sidecar boot
// (gatewaylog.SetProcessRunID) over the legacy DEFENSECLAW_RUN_ID
// env var so the middleware does not silently emit "" for
// foreground / `go run` / in-test invocations that never exported
// the env var. Returns "" if neither is set — downstream layers
// handle that the same as any other missing correlation field.
func currentProcessRunID() string {
	return gatewaylog.ProcessRunID()
}

// SessionIDHeader is the canonical header used by clients to scope
// a session across multiple requests. Accepting it is optional —
// clients that do not send one get no session_id on their events.
const SessionIDHeader = "X-DefenseClaw-Session-Id"

// Note: PolicyIDHeader is declared alongside the other v7 identity
// headers in agent_registry.go. We only add DestinationAppHeader +
// the length bounds here because the reader helpers live in this
// file.

// DestinationAppHeader names the downstream application the caller
// is routing this request to (e.g. "jira", "slack", "anthropic").
// Populated by the plugin fetch interceptor; the gateway only needs
// to read it so policy_id and destination_app land on the audit
// envelope alongside the other correlation fields.
const DestinationAppHeader = "X-DefenseClaw-Destination-App"

// maxPolicyIDLength / maxDestinationAppLength bound client-supplied
// identifiers for the same reason as maxRequestIDLength / maxSessionIDLength.
const (
	maxPolicyIDLength       = 128
	maxDestinationAppLength = 128
)

// maxSessionIDLength bounds client-supplied session identifiers for
// the same reason as maxRequestIDLength — every id is replicated
// across SQLite, JSONL, OTel, and Splunk HEC, so unbounded input is
// a cheap amplification vector.
const maxSessionIDLength = 128

// sessionIDCtxKey / traceIDCtxKey / agentIdentityCtxKey are
// unexported so only this package can write to the slots; readers
// go through the exported helpers below.
type (
	sessionIDCtxKey         struct{}
	traceIDCtxKey           struct{}
	agentIdentityCtxKey     struct{}
	pendingAgentRegistryKey struct{}
)

// pendingAgentRegistry pins the registry + inbound agent header that
// CorrelationMiddleware peeked. Authenticated handlers call
// PromoteSessionIfAuthenticated to upgrade the peeked identity to a
// minted entry once they have validated the request.
type pendingAgentRegistry struct {
	registry     *AgentRegistry
	inboundAgent string
}

func contextWithPendingAgentRegistry(ctx context.Context, reg *AgentRegistry, inboundAgent string) context.Context {
	if reg == nil {
		return ctx
	}
	return context.WithValue(ctx, pendingAgentRegistryKey{}, pendingAgentRegistry{registry: reg, inboundAgent: inboundAgent})
}

// PromoteSessionIfAuthenticated mints (or upgrades) the agent
// instance id for the request's session id once authentication has
// succeeded. Safe to call from any authenticated handler; idempotent
// when the session was already minted.
//
// The returned context carries the upgraded AgentIdentity AND a
// refreshed audit.CorrelationEnvelope so downstream audit /
// gatewaylog / OTel emissions include the newly minted
// agent_instance_id. When no pending registry is attached (test
// paths, public health checks) the function returns the input
// context unchanged.
func PromoteSessionIfAuthenticated(ctx context.Context) context.Context {
	if ctx == nil {
		return ctx
	}
	pending, ok := ctx.Value(pendingAgentRegistryKey{}).(pendingAgentRegistry)
	if !ok || pending.registry == nil {
		return ctx
	}
	sid := SessionIDFromContext(ctx)
	if sid == "" {
		return ctx
	}
	id := pending.registry.Resolve(ctx, sid, pending.inboundAgent)
	ctx = ContextWithAgentIdentity(ctx, id)
	// Refresh the audit envelope so the seven-field correlation
	// stamped by CorrelationMiddleware picks up the newly minted
	// agent_instance_id. Without this the envelope captured pre-
	// auth keeps AgentInstanceID="" and downstream audit rows lose
	// the join key for authenticated traffic.
	env := audit.EnvelopeFromContext(ctx)
	env.AgentID = id.AgentID
	env.AgentName = id.AgentName
	env.AgentInstanceID = id.AgentInstanceID
	return audit.ContextWithEnvelope(ctx, env)
}

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
// Callers that want fallback to the active OTel span should use
// SpanContextFromContext + .TraceID().String() — this helper only
// returns the explicitly-set value to keep the read path allocation-
// free for the hot audit emission path.
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

// policyIDFromHeaders returns the first non-empty policy id found
// in the canonical header, length-bounded and sanitized the same
// way as the request id. Empty string is the legal "not supplied"
// signal — downstream layers treat it like any other missing
// correlation field.
func policyIDFromHeaders(h http.Header) string {
	v := strings.TrimSpace(h.Get(PolicyIDHeader))
	if v == "" {
		return ""
	}
	if len(v) > maxPolicyIDLength {
		v = truncateToRuneBoundary(v, maxPolicyIDLength)
	}
	if !needsRequestIDClean(v) {
		return v
	}
	return sanitizeClientRequestID(v)
}

// destinationAppFromHeaders mirrors policyIDFromHeaders for the
// downstream-app label.
func destinationAppFromHeaders(h http.Header) string {
	v := strings.TrimSpace(h.Get(DestinationAppHeader))
	if v == "" {
		return ""
	}
	if len(v) > maxDestinationAppLength {
		v = truncateToRuneBoundary(v, maxDestinationAppLength)
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
// traceid is 32 lowercase hex characters. This helper performs the
// minimum shape check needed to extract the trace id for audit
// envelope use; proper end-to-end traceparent parsing happens in
// the OTel HTTP middleware (otelhttp.NewHandler) which wraps this
// chain.
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

// CorrelationMiddleware wraps next with session_id + trace_id +
// agent identity extraction. Must be installed AFTER
// requestIDMiddleware so request_id is already on the context.
//
// Wired into NewGuardrailProxy and NewAPIServer so every emission
// site (audit logger, OTel exporter, scanner pipeline) can read
// from AgentIdentityFromContext without re-parsing headers per call.
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
			// Adopt the inbound W3C traceparent into the audit
			// envelope ONLY for callers we trust to declare a
			// trace id. The OTel HTTP middleware wraps OUTSIDE
			// tokenAuth, so an unauthenticated, non-loopback
			// caller reaches this middleware before the auth
			// check. Mirroring the inbound traceparent into the
			// audit envelope for ANY caller would let such an
			// attacker stamp an arbitrary trace id onto
			// downstream audit rows for the rest of the request,
			// poisoning SIEM correlation joins and giving
			// attackers cheap noise injection into trace
			// dashboards.
			//
			// Trust gate: loopback only.
			//
			// Note this is INTENTIONALLY broader than the gate
			// `shouldExtractHookTrace` enforces in
			// `extractIncomingTraceContext` (which scopes the
			// OTel server span's parent extraction to
			// `/api/v1/<connector>/hook` + `/api/v1/codex/notify`).
			// The audit envelope's trace_id is a single field on
			// each persisted row; it does not propagate into
			// child spans, so the blast radius of a hostile
			// trace_id is bounded to "noise injection into
			// SIEM joins" — strictly less than the OTel span
			// tree splice the tighter gate defends against.
			//
			// Loopback is the trust boundary in practice: hook
			// scripts and the codex notify-bridge always POST
			// from 127.0.0.1, and the LLM forward-proxy hop
			// (`/v1/guardrail/evaluate`) likewise carries
			// `traceparent` from the legitimate agent → proxy →
			// gateway leg in dev workflows. A cross-network
			// caller has no legitimate reason to declare a
			// trace id on ANY route; for them we drop the
			// parent and fall back below to the local OTel
			// span's trace id (which is always server-issued
			// and matches whatever the OTel HTTP middleware
			// decided for the server span).
			if connector.IsLoopback(r) {
				if tid := traceIDFromHeaders(r.Header); tid != "" {
					ctx = ContextWithTraceID(ctx, tid)
				}
			}
			if TraceIDFromContext(ctx) == "" {
				if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
					ctx = ContextWithTraceID(ctx, span.SpanContext().TraceID().String())
				}
			}
			if registry != nil {
				// ("CorrelationMiddleware
				// mints unauthenticated agent sessions"):
				// CorrelationMiddleware runs BEFORE auth on
				// /health, /metrics, and the proxy chain.
				// Use ResolvePeek so we never mint a new
				// session entry from an unauthenticated
				// request — handlers that pass auth call
				// PromoteSessionIfAuthenticated below to
				// upgrade the peeked identity to a fully
				// minted entry. Combined with the LRU cap
				// in AgentRegistry, this prevents
				// unauthenticated callers from amplifying
				// sidecar memory by flooding unique
				// X-DefenseClaw-Session-Id values.
				id := registry.ResolvePeek(ctx, SessionIDFromContext(ctx), inboundAgent)
				if connector.IsLoopback(r) {
					if userID := sanitizeLLMEventUser(firstNonEmpty(
						r.Header.Get(llmEventUserIDHeader), r.Header.Get("X-User-Id"), r.Header.Get("X-User-ID"), r.Header.Get("X-User"),
					)); userID != "" {
						id.UserID = userID
					}
					if userName := sanitizeLLMEventUser(firstNonEmpty(
						r.Header.Get(llmEventUserNameHeader), r.Header.Get("X-User-Name"), r.Header.Get("X-Username"),
					)); userName != "" {
						id.UserName = userName
					}
				}
				ctx = ContextWithAgentIdentity(ctx, id)
				ctx = contextWithPendingAgentRegistry(ctx, registry, inboundAgent)
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

			// v7 closure: snapshot the resolved envelope into an
			// audit-package context key so every downstream
			// audit.Logger.LogEventCtx(ctx, ...) call auto-fills
			// the seven correlation fields (run_id, trace_id,
			// request_id, session_id, agent_id, agent_name,
			// agent_instance_id) without manual plumbing. The
			// sidecar_instance_id is filled by the audit store
			// choke point from the per-process UUID, so we do
			// not duplicate it here — keeping the envelope
			// focused on request-scoped values avoids
			// ambiguity when a test overrides it.
			id := AgentIdentityFromContext(ctx)
			audEnv := audit.CorrelationEnvelope{
				RunID:           currentProcessRunID(),
				TraceID:         TraceIDFromContext(ctx),
				RequestID:       RequestIDFromContext(ctx),
				SessionID:       SessionIDFromContext(ctx),
				AgentID:         id.AgentID,
				AgentName:       id.AgentName,
				AgentInstanceID: id.AgentInstanceID,
				PolicyID:        policyIDFromHeaders(r.Header),
				DestinationApp:  destinationAppFromHeaders(r.Header),
			}
			ctx = audit.ContextWithEnvelope(ctx, audEnv)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
