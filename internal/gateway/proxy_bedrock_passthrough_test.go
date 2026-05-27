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
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestPassthroughBedrockSigV4Preserved is the regression guard for the
// "AWS-aware passthrough" branch in handlePassthrough. AWS Bedrock signs
// requests with SigV4: the canonical signature covers the request body
// hash, the Host header, x-amz-* headers, and the Authorization line.
// Any mutation between sign and send invalidates the signature and AWS
// rejects the request with:
//
//	"The request signature we calculated does not match the signature
//	 you provided. Check your AWS Secret Access Key and signing
//	 method."
//
// This test asserts that for a Bedrock-classified request:
//
//   - Authorization is forwarded byte-for-byte verbatim (the fetch
//     interceptor's X-AI-Auth carrier does NOT replace the original).
//   - x-amz-date and x-amz-content-sha256 are preserved.
//   - The body bytes are not mutated (no notification injection, no
//     history laundering).
//   - DefenseClaw-internal proxy-hop headers (X-DC-Target-URL, X-AI-Auth,
//     X-DC-Auth) are stripped — they were never signed by the SDK and
//     must not leak to AWS.
func TestPassthroughBedrockSigV4Preserved(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	type captured struct {
		mu      sync.Mutex
		headers http.Header
		body    []byte
	}
	got := &captured{}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.mu.Lock()
		got.headers = r.Header.Clone()
		got.body = body
		got.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(
			`{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"stopReason":"end_turn"}`,
		))
	}))
	defer upstream.Close()

	// Register the loopback host as a "bedrock" provider so
	// inferProviderFromURL returns "bedrock" and the AWS-aware branch
	// runs. Without this the test would exit via the OpenAI-style
	// passthrough and tell us nothing about the new code path.
	origDomains := providerDomains
	providerDomains = append(providerDomains, providerDomainEntry{
		domain: "127.0.0.1",
		name:   "bedrock",
	})
	defer func() { providerDomains = origDomains }()

	const sigV4Auth = "AWS4-HMAC-SHA256 Credential=AKIATESTKEY/20260426/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-date;x-amz-content-sha256, Signature=deadbeef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	const amzDate = "20260426T084200Z"
	const amzSha = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	bedrockBody := []byte(`{"messages":[{"role":"user","content":[{"text":"hello"}]}]}`)

	req := httptest.NewRequest(
		http.MethodPost,
		"/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse-stream",
		bytes.NewReader(bedrockBody),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	// The fetch interceptor lifts the original Authorization into both
	// the original slot AND X-AI-Auth as a uniform proxy-hop carrier.
	req.Header.Set("Authorization", sigV4Auth)
	req.Header.Set("X-AI-Auth", sigV4Auth)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", amzSha)
	// Internal correlation headers MUST be stripped — they were never
	// signed and would be a privacy leak to upstream AWS.
	req.Header.Set("X-DC-Session-Id", "session-must-not-leak")
	req.Header.Set("X-Defenseclaw-Trace-Id", "trace-must-not-leak")
	req.RemoteAddr = "127.0.0.1:12345"

	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	got.mu.Lock()
	defer got.mu.Unlock()
	if got.headers == nil {
		t.Fatal("upstream did not receive the request")
	}

	if g := got.headers.Get("Authorization"); g != sigV4Auth {
		t.Errorf("Authorization mutated:\n  want: %q\n  got:  %q", sigV4Auth, g)
	}
	if g := got.headers.Get("X-Amz-Date"); g != amzDate {
		t.Errorf("X-Amz-Date mutated: want %q, got %q", amzDate, g)
	}
	if g := got.headers.Get("X-Amz-Content-Sha256"); g != amzSha {
		t.Errorf("X-Amz-Content-Sha256 mutated: want %q, got %q", amzSha, g)
	}

	if !bytes.Equal(got.body, bedrockBody) {
		t.Errorf("body mutated:\n  want: %q\n  got:  %q", bedrockBody, got.body)
	}

	for _, leaked := range []string{
		"X-Dc-Target-Url", "X-Ai-Auth", "X-Dc-Auth",
		"X-Dc-Session-Id", "X-Defenseclaw-Trace-Id",
	} {
		if v := got.headers.Get(leaked); v != "" {
			t.Errorf("internal header %s leaked to upstream AWS: %q", leaked, v)
		}
	}

	// Confirm the proxy did not swap in a fabricated Bearer-style
	// Authorization (the OpenAI-path failure mode).
	if strings.HasPrefix(got.headers.Get("Authorization"), "Bearer ") {
		t.Errorf("Authorization rewritten to Bearer form (would invalidate SigV4): %q",
			got.headers.Get("Authorization"))
	}
}
