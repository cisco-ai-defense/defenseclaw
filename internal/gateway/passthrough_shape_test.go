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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPassthroughThreeBranch exercises the Layer 1 classifier at the
// handlePassthrough seam: (known → forward), (shape → gated by
// AllowUnknownLLMDomains), (passthrough → always 403). The actual
// emitEgress side-effects are covered in events_test.go; this test
// only asserts the HTTP response.
func TestPassthroughThreeBranch(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()

	// Mock upstream that answers with an Anthropic-shaped JSON so
	// the proxy's inspector path is exercised to completion.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer upstream.Close()

	messagesBody := mustJSON(t, map[string]any{
		"model":    "claude-opus-4-5",
		"messages": []map[string]any{{"role": "user", "content": "hello"}},
	})
	nonLLMBody := []byte(`{"foo":"bar"}`)

	// Path-agnostic URL so we never collide with handleChatCompletion.
	const path = "/v1/messages"

	makeReq := func(targetURL string, body []byte) *http.Request {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DC-Target-URL", targetURL)
		req.Header.Set("X-AI-Auth", "Bearer sk-test")
		req.RemoteAddr = "127.0.0.1:12345"
		return req
	}

	t.Run("branch_known_forwards", func(t *testing.T) {
		proxy := newTestProxy(t, prov, insp, "action")
		// Temporarily register the upstream's host in providerDomains so
		// the known-provider allowlist matches.
		origDomains := providerDomains
		upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
		if idx := strings.Index(upstreamHost, ":"); idx > 0 {
			upstreamHost = upstreamHost[:idx]
		}
		providerDomains = append(providerDomains, struct {
			domain string
			name   string
		}{upstreamHost, "anthropic"})
		defer func() { providerDomains = origDomains }()

		rec := httptest.NewRecorder()
		proxy.handlePassthrough(rec, makeReq(upstream.URL, messagesBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for known branch, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("branch_shape_blocked_when_allow_unknown_disabled", func(t *testing.T) {
		proxy := newTestProxy(t, prov, insp, "action")
		proxy.cfg.AllowUnknownLLMDomains = false
		// Point at an UNKNOWN upstream. Body is messages-shaped.
		rec := httptest.NewRecorder()
		proxy.handlePassthrough(rec, makeReq("https://unknown-llm.example.test", messagesBody))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for shape-detected unknown host with allow off, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "allow_unknown_llm_domains") {
			t.Errorf("403 body should point operators at the opt-in flag, got: %s", rec.Body.String())
		}
	})

	// NOTE: the "allow_unknown enabled → forward" happy path is
	// covered indirectly. The mocked upstream runs on 127.0.0.1, which
	// our SSRF defense explicitly blocks even when
	// AllowUnknownLLMDomains=true (loopback is private). Proving the
	// positive branch end-to-end would require a non-loopback HTTP
	// listener, which is fragile in unit tests. The classifier itself
	// is covered by TestIsLLMShapedBody + TestIsPrivateHost.

	t.Run("branch_passthrough_blocked_for_unknown_non_llm_body", func(t *testing.T) {
		proxy := newTestProxy(t, prov, insp, "action")
		proxy.cfg.AllowUnknownLLMDomains = true // irrelevant — shape mismatch keeps us on the block branch
		rec := httptest.NewRecorder()
		proxy.handlePassthrough(rec, makeReq("https://unknown-non-llm.example.test", nonLLMBody))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for unknown host + non-LLM body, got %d", rec.Code)
		}
	})

	t.Run("branch_shape_private_ip_blocked_even_with_allow", func(t *testing.T) {
		proxy := newTestProxy(t, prov, insp, "action")
		proxy.cfg.AllowUnknownLLMDomains = true
		rec := httptest.NewRecorder()
		// IMDS-style target with an LLM-shaped body. SSRF defense in
		// depth must refuse this even when the operator opted into
		// unknown hosts.
		proxy.handlePassthrough(rec, makeReq("http://169.254.169.254", messagesBody))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for private IP with LLM-shaped body, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "private") {
			t.Errorf("403 body should mention private address, got: %s", rec.Body.String())
		}
	})
}
