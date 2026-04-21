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

import "context"

// CorrelationEnvelope mirrors the v7 fields every audit row is
// expected to carry when a request context is available. It is the
// single source of truth for "what ctx can feed into an audit
// Event" so call sites that accept a context.Context get the full
// envelope without plumbing seven parameters.
//
// Fields are plain strings because this struct is designed to be
// cheap to copy and stash in a context value. The audit package
// intentionally keeps this decoupled from gateway.AgentIdentity so
// non-HTTP callers (scanners, watchers, CLI commands) can populate
// it directly without pulling gateway as a dependency.
//
// All fields are optional. An empty field is semantically
// "unknown for this event" and round-trips as NULL in SQLite and
// an absent attribute on OTel/sinks.
type CorrelationEnvelope struct {
	RunID             string
	TraceID           string
	RequestID         string
	SessionID         string
	AgentID           string
	AgentName         string
	AgentInstanceID   string
	SidecarInstanceID string
	PolicyID          string
	DestinationApp   string
	ToolName          string
	ToolID            string
}

type envelopeCtxKey struct{}

// ContextWithEnvelope returns a copy of ctx carrying env. Meant to be
// set once by the gateway correlation middleware (or any callsite
// that already computed the envelope) so downstream audit calls in
// the same request scope pick it up for free.
//
// An empty envelope is still stored — tests need to be able to
// override the default by setting a partial envelope, and a later
// call that reads the ctx value treats unset fields as "no value".
func ContextWithEnvelope(ctx context.Context, env CorrelationEnvelope) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, envelopeCtxKey{}, env)
}

// EnvelopeFromContext returns the correlation envelope previously
// stashed via ContextWithEnvelope, or the zero value when no
// envelope is present. Never returns nil (envelopes are value types).
func EnvelopeFromContext(ctx context.Context) CorrelationEnvelope {
	if ctx == nil {
		return CorrelationEnvelope{}
	}
	v, _ := ctx.Value(envelopeCtxKey{}).(CorrelationEnvelope)
	return v
}

// ApplyEnvelope fills empty fields on e from env. Non-empty fields on
// e always win — matching the "caller intent is supreme" pattern used
// elsewhere in v7 stamping (provenance, sidecar id).
//
// Exported so call sites that bypass audit.Logger and write directly
// to audit.Store (e.g. the TUI-only guardrail-inspection row written
// by internal/gateway/proxy.go::recordTelemetry) can still stamp the
// same envelope the Logger.LogEventCtx path applies. Without this,
// the store-level row would silently diverge from its logger twin on
// every dimension the caller didn't copy by hand, which is exactly
// the review finding C1 gap.
func ApplyEnvelope(e *Event, env CorrelationEnvelope) {
	applyEnvelope(e, env)
}

// applyEnvelope is the internal (non-exported) entry point used by
// LogEventCtx / logActionWithEnvelope / logAlertWithEnvelope. Exported
// ApplyEnvelope delegates here so the stamping contract stays in
// exactly one place.
func applyEnvelope(e *Event, env CorrelationEnvelope) {
	if e == nil {
		return
	}
	if e.RunID == "" {
		e.RunID = env.RunID
	}
	if e.TraceID == "" {
		e.TraceID = env.TraceID
	}
	if e.RequestID == "" {
		e.RequestID = env.RequestID
	}
	if e.SessionID == "" {
		e.SessionID = env.SessionID
	}
	if e.AgentID == "" {
		e.AgentID = env.AgentID
	}
	if e.AgentName == "" {
		e.AgentName = env.AgentName
	}
	if e.AgentInstanceID == "" {
		e.AgentInstanceID = env.AgentInstanceID
	}
	if e.SidecarInstanceID == "" {
		e.SidecarInstanceID = env.SidecarInstanceID
	}
	if e.PolicyID == "" {
		e.PolicyID = env.PolicyID
	}
	if e.DestinationApp == "" {
		e.DestinationApp = env.DestinationApp
	}
	if e.ToolName == "" {
		e.ToolName = env.ToolName
	}
	if e.ToolID == "" {
		e.ToolID = env.ToolID
	}
}
