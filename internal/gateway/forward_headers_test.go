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
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestCopyForwardableHeaders_PassesThroughCommonProviderHeaders(t *testing.T) {
	src := http.Header{
		"Anthropic-Version":   []string{"2023-06-01"},
		"Anthropic-Beta":      []string{"messages-2024-09-04"},
		"Openai-Organization": []string{"org-abc123"},
		"User-Agent":          []string{"litellm/1.0"},
		"Accept":              []string{"application/json"},
		"Tenant-Id":           []string{"tenant-42"},
		"X-Region":            []string{"us-east-1"},
	}
	dst := http.Header{}
	n, err := CopyForwardableHeaders(dst, src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(src) {
		t.Errorf("forwarded count = %d, want %d", n, len(src))
	}
	for name, vals := range src {
		got := dst.Values(name)
		if len(got) != len(vals) {
			t.Errorf("header %q: got %d values, want %d", name, len(got), len(vals))
			continue
		}
		for i, v := range vals {
			if got[i] != v {
				t.Errorf("header %q[%d] = %q, want %q", name, i, got[i], v)
			}
		}
	}
}

func TestCopyForwardableHeaders_BlocklistedHeadersDropped(t *testing.T) {
	// This is the pre-existing blocklist preserved across the refactor:
	// proxy-hop, framework-internal, wire-framing (Host/Content-Length),
	// auth, and W3C trace context. The expanded set (cookies,
	// hop-by-hop per RFC 7230 §6.1, Baggage, Content-Type) is
	// intentionally commented out in forward_headers.go and therefore
	// NOT asserted here. See the "blocklist expansion" annotated block
	// in forward_headers.go for the danger ratings and re-enable
	// guidance.
	cases := []string{
		// Proxy-hop / framework-internal.
		"X-DC-Target-URL", "X-AI-Auth", "X-DC-Auth",
		// Wire framing.
		"Host", "Content-Length",
		// Auth — re-minted by the gateway.
		"Authorization", "X-API-Key", "Api-Key",
		// W3C trace context (Baggage is NOT in the active blocklist).
		"Traceparent", "Tracestate",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			src := http.Header{name: []string{"value"}}
			dst := http.Header{}
			n, err := CopyForwardableHeaders(dst, src)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != 0 {
				t.Errorf("expected blocklisted header %q to be dropped; got n=%d", name, n)
			}
			if dst.Get(name) != "" {
				t.Errorf("expected blocklisted header %q to be dropped; dst has %q", name, dst.Get(name))
			}
		})
	}
}

// TestCopyForwardableHeaders_CommentedOutBlocklistEntriesForward pins
// the explicit decision to commented-out the expanded blocklist (per the
// security review's recommendation to avoid silent behavior change).
// Each header here is documented in forward_headers.go with a danger
// rating; uncommenting any of them in production requires updating this
// test in lockstep so a future refactor cannot silently re-block them.
func TestCopyForwardableHeaders_CommentedOutBlocklistEntriesForward(t *testing.T) {
	commentedOut := map[string]string{
		"Cookie":              "session=abc",
		"Set-Cookie":          "x=y",
		"Proxy-Authorization": "Basic deadbeef",
		"Transfer-Encoding":   "chunked",
		"TE":                  "trailers",
		"Trailers":            "X-Trailer",
		"Connection":          "close",
		"Keep-Alive":          "timeout=5",
		"Upgrade":             "websocket",
		"Proxy-Authenticate":  "Basic realm=\"x\"",
		"Baggage":             "user-id=42",
		"Content-Type":        "application/json",
	}
	for name, value := range commentedOut {
		t.Run(name, func(t *testing.T) {
			src := http.Header{name: []string{value}}
			dst := http.Header{}
			_, err := CopyForwardableHeaders(dst, src)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := dst.Get(name); got != value {
				t.Errorf("expected %q to forward (commented out of blocklist); dst got %q", name, got)
			}
		})
	}
}

func TestCopyForwardableHeaders_BlocklistIsCaseInsensitive(t *testing.T) {
	src := http.Header{
		"AUTHORIZATION":            []string{"Bearer leaked"},
		"x-api-key":                []string{"leaked"},
		"hOsT":                     []string{"evil.example"},
		"X-Defenseclaw-Session-Id": []string{"abc"},
		"x-dc-auth":                []string{"Bearer dc"},
	}
	dst := http.Header{}
	n, _ := CopyForwardableHeaders(dst, src)
	if n != 0 {
		t.Errorf("expected all blocklisted headers to be dropped; got n=%d, dst=%v", n, dst)
	}
}

func TestCopyForwardableHeaders_DCAndDefenseClawPrefixDropped(t *testing.T) {
	src := http.Header{
		"X-DC-Anything":           []string{"leak"},
		"X-DefenseClaw-Whatever":  []string{"leak"},
		"X-Dc-Mixed-Case":         []string{"leak"},
		"x-defenseclaw-lowercase": []string{"leak"},
		// Negative control: not a DC prefix.
		"X-Something-Else": []string{"keep"},
	}
	dst := http.Header{}
	n, err := CopyForwardableHeaders(dst, src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("expected only X-Something-Else to forward; got n=%d, dst=%v", n, dst)
	}
	if dst.Get("X-Something-Else") != "keep" {
		t.Errorf("expected X-Something-Else=keep; dst=%v", dst)
	}
}

func TestCopyForwardableHeaders_InvalidHeaderNameRejected(t *testing.T) {
	// Space is not a valid tchar; RFC 7230 forbids it in field-name.
	src := http.Header{
		"Tenant Id": []string{"oops"},
	}
	dst := http.Header{}
	_, err := CopyForwardableHeaders(dst, src)
	if !errors.Is(err, ErrInvalidHeaderName) {
		t.Errorf("expected ErrInvalidHeaderName; got %v", err)
	}
}

func TestCopyForwardableHeaders_HeaderInjectionRejected(t *testing.T) {
	cases := map[string]string{
		"CR injection": "value\rEvil-Header: leaked",
		"LF injection": "value\nEvil-Header: leaked",
		"CRLF":         "value\r\nEvil-Header: leaked",
		"NUL byte":     "value\x00",
		"high byte":    "value\xff",
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			src := http.Header{"X-User-Tag": []string{payload}}
			dst := http.Header{}
			_, err := CopyForwardableHeaders(dst, src)
			if !errors.Is(err, ErrInvalidHeaderValue) {
				t.Errorf("expected ErrInvalidHeaderValue for %s payload; got %v", name, err)
			}
		})
	}
}

func TestCopyForwardableHeaders_HeaderValueAllowsTabAndPrintableASCII(t *testing.T) {
	src := http.Header{
		"X-Mixed-Case-Value": []string{"hello\tworld"},
		"X-Punctuation":      []string{"!@#$%^&*()_+-={}[];':,./<>?"},
	}
	dst := http.Header{}
	if _, err := CopyForwardableHeaders(dst, src); err != nil {
		t.Errorf("unexpected error on valid printable values: %v", err)
	}
}

func TestCopyForwardableHeaders_TooManyHeaders(t *testing.T) {
	src := http.Header{}
	for i := 0; i < maxForwardedHeaders+5; i++ {
		src[http.CanonicalHeaderKey("x-tag-"+itoa(i))] = []string{"v"}
	}
	dst := http.Header{}
	_, err := CopyForwardableHeaders(dst, src)
	if !errors.Is(err, ErrTooManyHeaders) {
		t.Errorf("expected ErrTooManyHeaders; got %v", err)
	}
}

func TestCopyForwardableHeaders_HeadersTooLarge(t *testing.T) {
	src := http.Header{
		"X-Big-Value": []string{strings.Repeat("a", maxForwardedBytes+1)},
	}
	dst := http.Header{}
	_, err := CopyForwardableHeaders(dst, src)
	if !errors.Is(err, ErrHeadersTooLarge) {
		t.Errorf("expected ErrHeadersTooLarge; got %v", err)
	}
}

func TestCopyForwardableHeaders_OverwritesPreExistingValue(t *testing.T) {
	// Set semantics: any pre-existing value on dst for a forwarded
	// header is overwritten, never duplicated. Prevents spoofing
	// where another code path already wrote the same canonical key.
	dst := http.Header{
		"X-Tenant-Id": []string{"stale-from-elsewhere"},
	}
	src := http.Header{
		"X-Tenant-Id": []string{"actual-from-agent"},
	}
	if _, err := CopyForwardableHeaders(dst, src); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := dst.Values("X-Tenant-Id")
	if len(got) != 1 || got[0] != "actual-from-agent" {
		t.Errorf("got %v, want exactly [actual-from-agent]", got)
	}
}

func TestCopyForwardableHeaders_NameCanonicalization(t *testing.T) {
	src := http.Header{
		"x-tenant-id":  []string{"t1"},
		"X-MIXED-cAsE": []string{"v"},
	}
	dst := http.Header{}
	if _, err := CopyForwardableHeaders(dst, src); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// dst.Get is case-insensitive but iterating verifies canonical key.
	if dst.Get("X-Tenant-Id") != "t1" {
		t.Errorf("X-Tenant-Id missing in dst: %v", dst)
	}
	if dst.Get("X-Mixed-Case") != "v" {
		t.Errorf("X-Mixed-Case missing in dst: %v", dst)
	}
}

func TestCopyForwardableHeaders_NilDestination(t *testing.T) {
	src := http.Header{"X": []string{"v"}}
	if _, err := CopyForwardableHeaders(nil, src); err == nil {
		t.Error("expected error on nil destination")
	}
}

func TestMergeConnectorExtraHeaders_BasicAndBlocklist(t *testing.T) {
	dst := http.Header{}
	extras := map[string]string{
		"X-Tenant":      "t1",
		"Authorization": "Bearer stolen", // blocked
		"X-DC-Auth":     "leak",          // blocked
	}
	n, err := MergeConnectorExtraHeaders(dst, extras)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("forwarded count = %d, want 1", n)
	}
	if dst.Get("X-Tenant") != "t1" {
		t.Errorf("X-Tenant missing: %v", dst)
	}
	if dst.Get("Authorization") != "" {
		t.Errorf("Authorization should have been blocklisted: %v", dst)
	}
}

func TestMergeConnectorExtraHeaders_ConnectorWinsOverDst(t *testing.T) {
	dst := http.Header{
		"X-Tenant": []string{"old-from-inbound"},
	}
	extras := map[string]string{
		"X-Tenant": "new-from-connector",
	}
	if _, err := MergeConnectorExtraHeaders(dst, extras); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := dst.Values("X-Tenant")
	if len(got) != 1 || got[0] != "new-from-connector" {
		t.Errorf("got %v, want [new-from-connector]", got)
	}
}

func TestMergeConnectorExtraHeaders_ValidatesPayload(t *testing.T) {
	dst := http.Header{}
	bad := map[string]string{"X-Evil": "x\r\nInjected: yes"}
	if _, err := MergeConnectorExtraHeaders(dst, bad); !errors.Is(err, ErrInvalidHeaderValue) {
		t.Errorf("expected ErrInvalidHeaderValue; got %v", err)
	}
}

func TestHTTPStatusForHeaderError(t *testing.T) {
	cases := map[error]int{
		ErrInvalidHeaderName:  http.StatusBadRequest,
		ErrInvalidHeaderValue: http.StatusBadRequest,
		ErrTooManyHeaders:     http.StatusRequestEntityTooLarge,
		ErrHeadersTooLarge:    http.StatusRequestEntityTooLarge,
		errors.New("other"):   http.StatusBadRequest,
	}
	for err, want := range cases {
		if got := httpStatusForHeaderError(err); got != want {
			t.Errorf("status for %v = %d, want %d", err, got, want)
		}
	}
}

func TestResultForHeaderError(t *testing.T) {
	cases := map[error]string{
		ErrInvalidHeaderName:  "rejected_invalid",
		ErrInvalidHeaderValue: "rejected_invalid",
		ErrTooManyHeaders:     "rejected_overflow",
		ErrHeadersTooLarge:    "rejected_overflow",
		errors.New("other"):   "rejected_invalid",
	}
	for err, want := range cases {
		if got := resultForHeaderError(err); got != want {
			t.Errorf("result for %v = %q, want %q", err, got, want)
		}
	}
}

// itoa is a tiny strconv shim so the test file doesn't need a strconv
// import for one call site.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [16]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
