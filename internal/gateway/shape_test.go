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
	"strings"
	"testing"
)

func TestIsLLMShapedBody(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantShape BodyShape
		wantMatch bool
	}{
		{"empty", "", BodyShapeNone, false},
		{"not JSON", "not a json body", BodyShapeNone, false},
		{"JSON array", `["not","an","object"]`, BodyShapeNone, false},
		{"no LLM keys", `{"foo":"bar","baz":1}`, BodyShapeNone, false},
		{"messages shape (OpenAI / Anthropic)",
			`{"model":"gpt","messages":[{"role":"user","content":"hi"}]}`, BodyShapeMessages, true},
		{"contents shape (Gemini)",
			`{"model":"x","contents":[{"role":"user","parts":[{"text":"hi"}]}]}`, BodyShapeContents, true},
		{"input string (Responses API)",
			`{"model":"gpt","input":"hello"}`, BodyShapeInput, true},
		{"input array (Responses API)",
			`{"model":"gpt","input":[{"role":"user"}]}`, BodyShapeInput, true},
		{"inputs array (legacy)",
			`{"inputs":[{"role":"user"}]}`, BodyShapeInput, true},
		{"prompt string (legacy completion)",
			`{"prompt":"hello"}`, BodyShapePrompt, true},
		{"messages wrong type (object)", `{"messages":{"not":"array"}}`, BodyShapeNone, false},
		{"prompt wrong type (array)", `{"prompt":[1,2]}`, BodyShapeNone, false},
		{"input wrong type (object)", `{"input":{"a":"b"}}`, BodyShapeNone, false},
		{"truncated messages (fallback probe)",
			`{"model":"gpt","messages":[{"role":"user","conten`, BodyShapeMessages, true},
		{"leading whitespace",
			"\n   {\"messages\":[{}]}", BodyShapeMessages, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := isLLMShapedBody([]byte(tt.body))
			if got != tt.wantShape || ok != tt.wantMatch {
				t.Fatalf("isLLMShapedBody(%q) = (%q,%v), want (%q,%v)",
					tt.body, got, ok, tt.wantShape, tt.wantMatch)
			}
		})
	}
}

func TestIsLLMShapedBodyCapsAtSixtyFourKiB(t *testing.T) {
	// Construct a 2 MiB payload with a valid "messages" prefix; the
	// detector must still classify it rather than OOM-parse the whole
	// thing.
	prefix := `{"messages":[{"role":"user","content":"`
	suffix := `"}]}`
	filler := strings.Repeat("x", 2*1024*1024)
	body := prefix + filler + suffix
	got, ok := isLLMShapedBody([]byte(body))
	if !ok {
		t.Fatalf("expected shape match, got none")
	}
	// The 64 KiB cap means the JSON itself won't parse cleanly, but
	// the fallback probe still finds "messages". Accept either
	// BodyShapeMessages (fallback) or the full parse result.
	if got != BodyShapeMessages {
		t.Fatalf("got shape=%q, want messages", got)
	}
}

func TestIsLLMPathSuffix(t *testing.T) {
	cases := map[string]bool{
		"https://api.openai.com/v1/chat/completions":                                     true,
		"https://api.anthropic.com/v1/messages":                                          true,
		"https://generativelanguage.googleapis.com/v1beta/models/gemini:generateContent": true,
		"https://bedrock-runtime.us-east-1.amazonaws.com/model/foo/converse":             true,
		"http://localhost:11434/api/chat":                                                true,
		"https://api.openai.com/v1/responses":                                            true,
		"https://github.com/foo/bar":                                                     false,
		"https://registry.npmjs.org/express":                                             false,
		"":                                                                               false,
		"://broken-url":                                                                  false,
	}
	for u, want := range cases {
		if got := isLLMPathSuffix(u); got != want {
			t.Errorf("isLLMPathSuffix(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestIsKnownSafeDomain(t *testing.T) {
	cases := map[string]bool{
		"https://github.com/foo":                     true,
		"https://raw.githubusercontent.com/foo":      true,
		"https://sub.sentry.io/" + `x`:               true,
		"https://registry.npmjs.org/express":         true,
		"https://api.openai.com/v1/chat/completions": false,
		"https://api.anthropic.com/v1/messages":      false,
		"http://localhost:11434/api/chat":            false,
		"":                                           false,
	}
	for u, want := range cases {
		if got := isKnownSafeDomain(u); got != want {
			t.Errorf("isKnownSafeDomain(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestIsPrivateHost(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1":           true,
		"10.0.0.1:8080":      true,
		"127.0.0.1":          true,
		"127.0.0.1:80":       true,
		"169.254.169.254":    true, // cloud IMDS
		"192.168.1.5":        true,
		"[::1]:8080":         true,
		"::1":                true,
		"fe80::1":            true,
		"1.2.3.4":            false,
		"8.8.8.8":            false,
		"api.openai.com":     false, // hostname, not IP literal
		"api.openai.com:443": false,
		"":                   false,
	}
	for h, want := range cases {
		if got := isPrivateHost(h); got != want {
			t.Errorf("isPrivateHost(%q) = %v, want %v", h, got, want)
		}
	}
}

// TestIsPrivateHost_HostnameResolvesToLoopback pins PR #141 audit M1.
// Prior to M1 the function returned false for any non-IP-literal input
// without consulting DNS — so an attacker-controlled `evil.example`
// that resolved to 127.0.0.1 (or 169.254.169.254 cloud metadata) would
// fly under the SSRF guard. We use `localhost` here because it is
// guaranteed to resolve to a loopback address on every platform's
// default resolver chain (`/etc/hosts` on Unix, the equivalent on
// Windows) and does not require live external DNS.
func TestIsPrivateHost_HostnameResolvesToLoopback(t *testing.T) {
	cases := []string{
		"localhost",
		"localhost:8080",
	}
	for _, h := range cases {
		if !isPrivateHost(h) {
			t.Errorf("isPrivateHost(%q) = false, want true (DNS-resolved hostname pointing at loopback)", h)
		}
	}
}

// TestIsPrivateHost_IPv6Zones pins ().
//
// Pre-fix: net.ParseIP returns nil on a zone-qualified IPv6 literal like
// "::1%lo0" or "fe80::1%lo0", so isPrivateHost fell through to DNS
// resolution (which fails for an IP literal), returned false, and let
// callers dial loopback / link-local destinations even though
// allow_unknown_llm_domains was supposed to short-circuit on private IPs.
//
// Post-fix: stripIPv6Zone removes the "%zone" suffix before ParseIP, so
// every scoped form of a private literal is correctly classified.
func TestIsPrivateHost_IPv6Zones(t *testing.T) {
	cases := map[string]bool{
		// Bare scoped loopback / link-local — bypass surface.
		"::1%lo0":             true,
		"fe80::1%lo0":         true,
		"fe80::1%eth0":        true,
		"fe80::dead:beef%en0": true,
		// Bracketed forms with port — same surface, different syntax.
		"[::1%lo0]:8080":           true,
		"[fe80::1%lo0]:443":        true,
		"[fe80::dead:beef%en0]:80": true,
		// Public IPv6 should still pass through (no false positives).
		"2001:db8::1":       false,
		"[2001:db8::1]:443": false,
	}
	for h, want := range cases {
		if got := isPrivateHost(h); got != want {
			t.Errorf("isPrivateHost(%q) = %v, want %v", h, got, want)
		}
	}
}

// TestStripIPv6Zone unit-tests the zone-strip helper.
func TestStripIPv6Zone(t *testing.T) {
	cases := map[string]string{
		"::1%lo0":             "::1",
		"fe80::1%eth0":        "fe80::1",
		"fe80::dead:beef%en0": "fe80::dead:beef",
		// IPv4 / unscoped IPv6 / hostnames pass through unchanged.
		"127.0.0.1":      "127.0.0.1",
		"2001:db8::1":    "2001:db8::1",
		"api.openai.com": "api.openai.com",
		"":               "",
	}
	for in, want := range cases {
		if got := stripIPv6Zone(in); got != want {
			t.Errorf("stripIPv6Zone(%q) = %q, want %q", in, got, want)
		}
	}
}
