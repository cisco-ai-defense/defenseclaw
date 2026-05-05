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
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/google/uuid"
)

// Phase 5: request_id threading.
//
// Every proxy request gets a stable correlation identifier that flows
// through every log line, span, SQLite row, JSONL event, and Splunk
// payload. Clients can supply their own via the RequestIDHeader —
// useful when upstream services already mint a trace id and want
// DefenseClaw's audit trail to key on the same value — otherwise we
// mint a v4 UUID.
//
// The context key is typed and unexported so no other package can
// stuff arbitrary values into the slot. Consumers only see the
// exported helpers RequestIDFromContext / ContextWithRequestID.

// RequestIDHeader is the canonical HTTP header used for correlation
// between clients and DefenseClaw. We accept either this header or
// the common industry conventions X-Request-Id / X-Correlation-Id
// so existing instrumentation libraries "just work".
const RequestIDHeader = "X-DefenseClaw-Request-Id"

// maxRequestIDLength bounds how much of a client-supplied request ID
// we trust. Every correlation ID is fanned out to SQLite,
// gateway.jsonl, OTel attributes, and the Splunk HEC envelope, so a
// malicious or misconfigured client that sends a 1 MiB "request id"
// header would get that value replicated across every logging
// system — a cheap denial-of-service amplification. 128 chars is
// generous enough to fit a UUIDv4 (36), a GUID (38), an Envoy
// request id plus a vendor prefix (~64), and most tracing library
// conventions, while bounding cardinality and storage. Anything
// longer is silently truncated; we do not reject the request —
// correlation is a convenience, not a trust boundary.
const maxRequestIDLength = 128

// requestIDCtxKey is unexported so only this package can write to the
// slot — callers must go through ContextWithRequestID.
type requestIDCtxKey struct{}

// ContextWithRequestID returns a copy of ctx annotated with id.
// An empty id is a no-op so this is safe to call unconditionally.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDCtxKey{}, id)
}

// RequestIDFromContext returns the correlation ID attached to ctx, or
// the empty string if none has been minted. Never panics on a nil
// ctx (production code shouldn't pass one, but tests sometimes do).
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(requestIDCtxKey{}).(string)
	return v
}

// requestIDFromHeaders returns the first non-empty correlation ID
// found in any of the recognised request-ID header names, or "".
// Clients commonly use X-Request-Id (OpenTelemetry, Envoy) or
// X-Correlation-Id (Microsoft, New Relic); we accept both alongside
// our canonical header so integrations don't require header
// rewriting.
func requestIDFromHeaders(h http.Header) string {
	for _, name := range []string{RequestIDHeader, "X-Request-Id", "X-Correlation-Id"} {
		if v := strings.TrimSpace(h.Get(name)); v != "" {
			return sanitizeClientRequestID(v)
		}
	}
	return ""
}

// sanitizeClientRequestID normalizes a client-supplied correlation
// identifier so it is safe to replicate across every observability
// sink. Three concerns are addressed:
//
//  1. Length. Go's net/http already strips CR/LF from header values,
//     but a pathological (or malicious) client can still send a
//     multi-kilobyte header. Because the ID is fanned out to SQLite,
//     JSONL, OTel attributes, and Splunk HEC, unbounded input is a
//     cheap amplification vector — truncating to maxRequestIDLength
//     bounds the per-request storage cost.
//  2. UTF-8 integrity. A naive byte-index truncation at the length
//     cap can land in the middle of a multi-byte rune and leave
//     invalid UTF-8 in the tail, which would poison JSON encoders
//     (json.Marshal replaces invalid sequences with U+FFFD in some
//     configurations) and SQLite TEXT columns (which expect valid
//     UTF-8). We walk back to the preceding rune boundary so the
//     result is always a well-formed UTF-8 string.
//  3. Log injection defence-in-depth. We drop any remaining control
//     characters (ASCII < 0x20, plus DEL). Production-grade HTTP
//     stacks already enforce this, but a defence-in-depth strip is
//     cheap and keeps the field trivially safe to splice into
//     structured log fields that might be consumed by permissive
//     log viewers. Non-ASCII runes are preserved — the cardinality
//     cap above is what bounds abuse, not an ASCII filter.
//
// The function is intentionally lossy: we never reject the request
// because correlation IDs are a convenience, not a trust boundary.
func sanitizeClientRequestID(id string) string {
	preTrunc := id
	if len(id) > maxRequestIDLength {
		id = truncateToRuneBoundary(id, maxRequestIDLength)
		if preTrunc != id {
			noteCorrelationNormalized(RequestIDHeader, "truncated")
		}
	}
	if !needsRequestIDClean(id) {
		return id
	}
	// Walk by rune, not by byte, so multi-byte code points survive
	// the control-character strip. ASCII control characters are
	// dropped; everything else (including printable Unicode) is
	// preserved verbatim.
	b := make([]byte, 0, len(id))
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b = utf8.AppendRune(b, r)
	}
	out := string(b)
	if out != id {
		noteCorrelationNormalized(RequestIDHeader, "sanitized_control")
	}
	return out
}

func emitGatewayError(ctx context.Context, sub gatewaylog.Subsystem, code gatewaylog.ErrorCode, msg string, cause error) {
	payload := &gatewaylog.ErrorPayload{
		Subsystem: string(sub),
		Code:      string(code),
		Message:   msg,
	}
	if cause != nil {
		payload.Cause = cause.Error()
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		Error:     payload,
	})
}

// correlationNormRL rate-limits noteCorrelationNormalized to once per minute
// per (header_name, reason) tuple.
var correlationNormRL sync.Map // string -> time.Time

func noteCorrelationNormalized(headerName, reason string) {
	key := headerName + "\x00" + reason
	now := time.Now()
	if v, ok := correlationNormRL.Load(key); ok {
		if now.Sub(v.(time.Time)) < time.Minute {
			return
		}
	}
	correlationNormRL.Store(key, now)
	// Rate-limited diagnostic — runs outside any request context, so
	// we pass context.Background() and let Writer stamp the sidecar id.
	emitGatewayError(context.Background(), gatewaylog.SubsystemCorrelation, gatewaylog.ErrCodeInvalidHeader,
		fmt.Sprintf("correlation header normalized (%s)", reason), nil)
	// TODO(track0-followup): bump defenseclaw.correlation.normalized{header_name, reason} counter when instrument lands.
}

// truncateToRuneBoundary returns s truncated to at most max bytes,
// walking back to a rune boundary if the naive byte cut would split
// a multi-byte UTF-8 sequence. Caller must have already checked
// len(s) > max; the extra bounds guard keeps the helper
// self-contained for direct unit testing.
//
// The returned string is always valid UTF-8 up to its final rune,
// and its byte length is always <= max. If max<=0 or every prefix
// is malformed, the empty string is returned — a safe no-op for the
// correlation-ID use case.
func truncateToRuneBoundary(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	// Walk back over UTF-8 continuation bytes (0b10xxxxxx) until we
	// land on a rune-start byte. RuneStart says "b is the first
	// byte of an encoded rune", which is true for ASCII (<0x80)
	// and for UTF-8 leaders (>=0xC0).
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	// Decide whether the rune that starts at cut fits within the
	// cap. If it does, include it; if it doesn't, return the
	// prefix that ended on the previous rune boundary. The zero-
	// size path (cut at end of string) can't trigger here because
	// len(s) > max guarantees s[cut:] is non-empty.
	if _, size := utf8.DecodeRuneInString(s[cut:]); cut+size <= max {
		return s[:cut+size]
	}
	return s[:cut]
}

// needsRequestIDClean is a fast scan that avoids the allocation in
// sanitizeClientRequestID for the common case where every byte is
// already a printable ASCII character.
func needsRequestIDClean(id string) bool {
	for i := 0; i < len(id); i++ {
		if c := id[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// mintRequestID returns a fresh v4 UUID. Kept as a function so tests
// can shadow it via a package-level variable if deterministic IDs
// are needed (no plans to do this today; UUID collisions in tests
// are vanishingly unlikely).
func mintRequestID() string {
	return uuid.NewString()
}

// requestIDMiddleware wraps next with a middleware that ensures every
// request carries a request_id:
//
//  1. If the client sent one via RequestIDHeader / X-Request-Id /
//     X-Correlation-Id, we honour it verbatim.
//  2. Otherwise we mint a fresh v4 UUID.
//
// The final ID is exposed back to the client via the response header
// of the same name so they can cross-reference support tickets with
// DefenseClaw's audit log without having to dig through their own
// instrumentation.
//
// Downstream handlers read the ID from the request context using
// RequestIDFromContext; they do not need to be aware of the HTTP
// layer.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestIDFromHeaders(r.Header)
		if id == "" {
			id = mintRequestID()
		}
		// Surface the chosen ID back to the client early — before
		// we call ServeHTTP — so even streaming responses (SSE) that
		// flush on the first chunk still carry the correlation
		// header in their initial frame.
		w.Header().Set(RequestIDHeader, id)
		r = r.WithContext(ContextWithRequestID(r.Context(), id))
		next.ServeHTTP(w, r)
	})
}

// requestIDMiddleware is exposed as a method on GuardrailProxy purely
// for discoverability at the call site (the proxy wires the chain
// inside NewGuardrailProxy and seeing "p.requestIDMiddleware" makes
// the ownership obvious). The implementation itself needs no state
// so it delegates to the package-level helper, which is reused by
// the API server and any other HTTP handler that wants the same
// correlation behavior.
func (p *GuardrailProxy) requestIDMiddleware(next http.Handler) http.Handler {
	return requestIDMiddleware(next)
}

const maxUserAgentLogLength = 256

// TruncateUserAgent256 bounds user-agent strings for auth-failure payloads.
func TruncateUserAgent256(ua string) string {
	if len(ua) <= maxUserAgentLogLength {
		return ua
	}
	return ua[:maxUserAgentLogLength]
}

// ClientIPRedacted returns a privacy-preserving client address for logs
// (IPv4 /24, IPv6 prefix simplified to first 4 hextets + "::/48" style stub).
func ClientIPRedacted(r *http.Request) string {
	if r == nil {
		return ""
	}
	ipStr := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if ipStr != "" {
		ipStr = strings.TrimSpace(strings.Split(ipStr, ",")[0])
	} else {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ipStr = r.RemoteAddr
		} else {
			ipStr = host
		}
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
	}
	// IPv6: keep first 4 hextets as a coarse prefix (not strict CIDR math).
	s := ip.String()
	parts := strings.Split(s, ":")
	if len(parts) >= 4 {
		return strings.Join(parts[:4], ":") + ":…/48"
	}
	return s
}

// otelHTTPServerMiddleware creates a server span for each request and
// records HTTP semantic attributes. Inner middleware should call
// enrichHTTPSpanFromContext so defenseclaw.* correlation fields land on
// the same span.
func otelHTTPServerMiddleware(serverName string, next http.Handler) http.Handler {
	tracer := otel.Tracer("defenseclaw")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := r.URL.Path
		if r.Pattern != "" {
			route = r.Pattern
		}
		spanName := r.Method + " " + route
		ctx, span := tracer.Start(r.Context(), spanName,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("defenseclaw.http.server", serverName)),
		)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))
		status := sw.status
		if status >= 400 {
			span.SetStatus(codes.Error, http.StatusText(status))
		}
		span.SetAttributes(
			semconv.HTTPRequestMethodKey.String(r.Method),
			semconv.HTTPRouteKey.String(route),
			semconv.HTTPResponseStatusCode(status),
		)
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		if h, p, err := net.SplitHostPort(host); err == nil {
			span.SetAttributes(
				semconv.ServerAddressKey.String(h),
				semconv.ServerPortKey.String(p),
			)
		} else if host != "" {
			span.SetAttributes(semconv.ServerAddressKey.String(host))
		}
		span.SetAttributes(semconv.URLPath(r.URL.Path))
		q := r.URL.RawQuery
		if q != "" {
			span.SetAttributes(semconv.URLQuery(sanitizeQueryForSpan(q)))
		}
		span.End()
	})
}

func sanitizeQueryForSpan(q string) string {
	if len(q) > 512 {
		return q[:512] + "…"
	}
	return q
}

// ScanCorrelationFromContext bundles the correlation + agent
// identity already resolved by the HTTP middleware stack into a
// typed value the audit package can accept without importing
// gateway (that would be an import cycle). Every field is optional;
// an empty result is legal (e.g. pre-session admin APIs).
//
// Falls back to the active OTel span's trace id when the explicit
// context value is empty so downstream logs can still correlate
// with the span that produced them.
func ScanCorrelationFromContext(ctx context.Context) audit.ScanCorrelation {
	if ctx == nil {
		return audit.ScanCorrelation{}
	}
	aid := AgentIdentityFromContext(ctx)
	tid := TraceIDFromContext(ctx)
	if tid == "" {
		if sp := trace.SpanFromContext(ctx); sp != nil && sp.SpanContext().IsValid() {
			tid = sp.SpanContext().TraceID().String()
		}
	}
	return audit.ScanCorrelation{
		RequestID:       RequestIDFromContext(ctx),
		SessionID:       SessionIDFromContext(ctx),
		TraceID:         tid,
		AgentID:         aid.AgentID,
		AgentName:       aid.AgentName,
		AgentInstanceID: aid.AgentInstanceID,
	}
}

// enrichHTTPSpanFromContext stamps defenseclaw correlation identifiers onto
// the active span (the HTTP server span when otelHTTPServerMiddleware is outermost).
func enrichHTTPSpanFromContext(ctx context.Context) {
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	if id := RequestIDFromContext(ctx); id != "" {
		span.SetAttributes(attribute.String("defenseclaw.request_id", id))
	}
	if sid := SessionIDFromContext(ctx); sid != "" {
		span.SetAttributes(attribute.String("gen_ai.conversation.id", sid))
	}
	aid := AgentIdentityFromContext(ctx)
	if aid.AgentID != "" {
		span.SetAttributes(attribute.String("defenseclaw.agent_id", aid.AgentID))
	}
	if aid.AgentType != "" {
		span.SetAttributes(attribute.String("gen_ai.agent.type", aid.AgentType))
	}
	if aid.AgentInstanceID != "" {
		span.SetAttributes(attribute.String("defenseclaw.agent_instance_id", aid.AgentInstanceID))
	}
	tid := TraceIDFromContext(ctx)
	if tid == "" {
		tid = span.SpanContext().TraceID().String()
	}
	if tid != "" {
		span.SetAttributes(attribute.String("defenseclaw.trace_id", tid))
	}
}
