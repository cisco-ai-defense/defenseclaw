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
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// uuidV4Pattern loosely matches a v4 UUID so we can assert the
// mint-path returns something that looks like the intended shape
// without pinning on a specific library's formatting quirks.
var uuidV4Pattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func TestContextWithRequestID_EmptyIsNoOp(t *testing.T) {
	ctx := context.Background()
	got := ContextWithRequestID(ctx, "")
	if got != ctx {
		t.Fatalf("empty id should return the same ctx; got %v want %v", got, ctx)
	}
}

func TestContextWithRequestID_RoundTrip(t *testing.T) {
	ctx := ContextWithRequestID(context.Background(), "abc-123")
	if got := RequestIDFromContext(ctx); got != "abc-123" {
		t.Fatalf("RequestIDFromContext=%q want abc-123", got)
	}
}

func TestRequestIDFromContext_NilCtx(t *testing.T) {
	// A nil ctx must not panic. Prod code doesn't pass one but we've
	// seen tests do it via background helpers.
	if got := RequestIDFromContext(nil); got != "" { //nolint:staticcheck // intentional nil ctx test
		t.Fatalf("nil ctx must return empty; got %q", got)
	}
}

func TestRequestIDFromHeaders_PrefersCanonical(t *testing.T) {
	h := http.Header{}
	h.Set("X-Request-Id", "fallback")
	h.Set(RequestIDHeader, "canonical")
	if got := requestIDFromHeaders(h); got != "canonical" {
		t.Fatalf("canonical header should win; got %q", got)
	}
}

func TestRequestIDFromHeaders_AcceptsIndustryHeaders(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"xrequestid", "X-Request-Id", "envoy-1"},
		{"xcorrelationid", "X-Correlation-Id", "new-relic-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			h.Set(tc.header, tc.want)
			if got := requestIDFromHeaders(h); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestRequestIDFromHeaders_TrimsWhitespace(t *testing.T) {
	h := http.Header{}
	h.Set(RequestIDHeader, "   spaced-out   ")
	if got := requestIDFromHeaders(h); got != "spaced-out" {
		t.Fatalf("got %q want spaced-out", got)
	}
}

func TestMintRequestID_LooksLikeUUID(t *testing.T) {
	id := mintRequestID()
	if !uuidV4Pattern.MatchString(id) {
		t.Fatalf("minted id %q does not look like a v4 UUID", id)
	}
}

func TestRequestIDMiddleware_MintsWhenAbsent(t *testing.T) {
	var captured string
	h := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = RequestIDFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if captured == "" {
		t.Fatal("middleware should have minted a request id")
	}
	if !uuidV4Pattern.MatchString(captured) {
		t.Fatalf("minted id %q does not look like a v4 UUID", captured)
	}
	echoed := rec.Header().Get(RequestIDHeader)
	if echoed != captured {
		t.Fatalf("response header %q should equal context id %q", echoed, captured)
	}
}

func TestRequestIDMiddleware_HonoursClientSupplied(t *testing.T) {
	var captured string
	h := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = RequestIDFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set(RequestIDHeader, "client-supplied-id")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if captured != "client-supplied-id" {
		t.Fatalf("middleware should echo client id; got %q", captured)
	}
	if got := rec.Header().Get(RequestIDHeader); got != "client-supplied-id" {
		t.Fatalf("response header should echo back; got %q", got)
	}
}

// TestSanitizeClientRequestID_BoundsLength verifies the hard cap on
// client-supplied correlation IDs. Without this guard, a misbehaving
// client could ship multi-kilobyte request IDs that would be
// replicated to every observability sink (SQLite, gateway.jsonl,
// Splunk HEC, OTel), amplifying a single bad request into a
// denial-of-service vector on storage and indexing cost.
func TestSanitizeClientRequestID_BoundsLength(t *testing.T) {
	oversized := strings.Repeat("a", maxRequestIDLength+1024)
	got := sanitizeClientRequestID(oversized)
	if len(got) != maxRequestIDLength {
		t.Fatalf("truncated len=%d want %d", len(got), maxRequestIDLength)
	}
}

// TestSanitizeClientRequestID_StripsControlChars is defence-in-depth:
// Go's HTTP stack already refuses CR/LF in headers, but a careful
// strip here keeps IDs safe to splice into any log viewer that is
// lenient about control characters.
func TestSanitizeClientRequestID_StripsControlChars(t *testing.T) {
	raw := "clean\x00nul\x07bel\x1bescape-id"
	got := sanitizeClientRequestID(raw)
	if got != "cleannulbelescape-id" {
		t.Fatalf("got %q want cleannulbelescape-id", got)
	}
}

// TestSanitizeClientRequestID_PassThrough exercises the fast path —
// a printable ASCII identifier well under the length cap must be
// returned byte-for-byte, with no allocations and no transformation.
func TestSanitizeClientRequestID_PassThrough(t *testing.T) {
	id := "0123-abcd-EF01-UUID"
	if got := sanitizeClientRequestID(id); got != id {
		t.Fatalf("pass-through altered id: got %q want %q", got, id)
	}
}

// TestRequestIDFromHeaders_AppliesSanitizer ensures the middleware
// path (header -> context -> audit event) never bypasses the
// bounding/stripping contract. We use control characters because
// a silently-broken sanitizer would flow through to every sink.
func TestRequestIDFromHeaders_AppliesSanitizer(t *testing.T) {
	h := http.Header{}
	h.Set(RequestIDHeader, "line1\rline2") // CR is stripped by net/http too, but test belt-and-braces
	got := requestIDFromHeaders(h)
	if strings.ContainsAny(got, "\r\n\x00") {
		t.Fatalf("sanitizer leaked control chars: %q", got)
	}
}

func TestRequestIDMiddleware_HonoursIndustryHeader(t *testing.T) {
	var captured string
	h := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = RequestIDFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Correlation-Id", "corr-42")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if captured != "corr-42" {
		t.Fatalf("middleware should honour X-Correlation-Id; got %q", captured)
	}
	// The echo-back always uses our canonical header so downstream
	// systems only have to learn one name.
	if got := rec.Header().Get(RequestIDHeader); got != "corr-42" {
		t.Fatalf("response header should use canonical name; got %q", got)
	}
}
