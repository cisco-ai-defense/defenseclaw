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
	"unicode/utf8"
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

// TestSanitizeClientRequestID_UTF8Safe pins the contract that the
// sanitizer never returns a string containing invalid UTF-8, even
// when the byte-level length cap lands in the middle of a multi-byte
// rune. Before the M3 fix, truncation was a naive byte slice which
// could leave a dangling 0xC0..0xFD leader at the tail; that tail
// would corrupt JSON encoders, SQLite TEXT columns, and the OTel
// attribute protobuf encoding (which validates UTF-8). Every sink in
// the fan-out expects valid UTF-8, so this invariant must hold.
func TestSanitizeClientRequestID_UTF8Safe(t *testing.T) {
	// A string of é (0xC3 0xA9) chars designed so the byte cap lands
	// mid-rune: 64 x é = 128 bytes at the cap, plus one more é means
	// maxRequestIDLength+2 bytes. A naive cut at 128 would split the
	// 65th é and leave 0xC3 at the tail.
	raw := strings.Repeat("é", (maxRequestIDLength/2)+1)
	if len(raw) <= maxRequestIDLength {
		t.Fatalf("test setup: want oversized input, got len=%d", len(raw))
	}
	got := sanitizeClientRequestID(raw)
	if !utf8.ValidString(got) {
		t.Fatalf("sanitizer returned invalid UTF-8: % x", []byte(got))
	}
	if len(got) > maxRequestIDLength {
		t.Fatalf("sanitizer exceeded length cap: len=%d max=%d",
			len(got), maxRequestIDLength)
	}
	// Length must have shrunk to the largest rune-aligned prefix
	// that fits in the cap — 64 é = 128 bytes for the default cap.
	if len(got)%2 != 0 {
		t.Fatalf("result byte length %d is not rune-aligned", len(got))
	}
}

// TestSanitizeClientRequestID_PreservesUnicode verifies that the
// control-char strip is rune-aware, not byte-aware. If the strip
// loop walked bytes, multi-byte UTF-8 leaders (>= 0xC0) would never
// match the control range but continuation bytes (0x80-0xBF) would
// also never match, so the original implementation was already safe
// on that axis; this test locks the behaviour in so a future
// "optimise by stripping < 0x20" refactor can't silently break
// Unicode correlation IDs from international services.
func TestSanitizeClientRequestID_PreservesUnicode(t *testing.T) {
	// A non-ASCII id that's under the length cap — no truncation,
	// no control chars, should pass through identically.
	id := "req-éàü-中文-🙂"
	got := sanitizeClientRequestID(id)
	if got != id {
		t.Fatalf("unicode identifier mutated: got %q want %q", got, id)
	}
}

// TestTruncateToRuneBoundary_Cases drives the helper directly so we
// can pin every branch — the naive-cut-works case, the walk-back
// case, the rune-doesn't-fit case, and the degenerate
// max<=0 / len(s)<=max inputs.
func TestTruncateToRuneBoundary_Cases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"max_zero", "abc", 0, ""},
		{"max_negative", "abc", -1, ""},
		{"shorter_than_max", "abc", 10, "abc"},
		{"exact_length", "abc", 3, "abc"},
		{"ascii_cut", "abcdef", 3, "abc"},
		{"cut_lands_on_runestart_that_fits", "abcdé", 4, "abcd"},
		{"cut_lands_mid_rune_walk_back_include", "abcdé", 5, "abcd"},
		{"cut_lands_mid_rune_drop_rune", "aéb", 2, "a"},
		{"multibyte_cluster_fits_exactly", "aé", 3, "aé"},
		{"emoji_truncation", "hello🙂world", 7, "hello"}, // 🙂 is 4 bytes; 5+4=9>7 so drop
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateToRuneBoundary(tc.in, tc.max)
			if got != tc.want {
				t.Fatalf("truncateToRuneBoundary(%q, %d) = %q, want %q",
					tc.in, tc.max, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("result is not valid UTF-8: % x", []byte(got))
			}
			if len(got) > tc.max && tc.max > 0 {
				t.Fatalf("result len=%d exceeds cap %d", len(got), tc.max)
			}
		})
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
