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
	"encoding/json"
	"net"
	"net/url"
	"strings"
)

// Layer 1 (shape detection) mirrors extensions/defenseclaw/src/fetch-interceptor.ts.
// The goal is the same: the Go proxy already enforces an allowlist against
// providers.json, but a request that reaches this proxy with an unknown
// hostname (manually configured mitmproxy, custom self-hosted OpenAI-compat
// endpoint, or a new provider we haven't indexed yet) would be rejected
// outright. Layer 1 gives us a middle branch: if the body SHAPE looks like
// an LLM call, we know enough to at least run guardrails and audit it.

// LLMPathSuffixes are URL path fragments that identify LLM/agent APIs.
// Keep this in LOCKSTEP with the TS-side LLM_PATH_SUFFIXES in
// extensions/defenseclaw/src/fetch-interceptor.ts — the provider-coverage
// contract test drives both surfaces off internal/gateway/shape_test.go
// fixtures.
var LLMPathSuffixes = []string{
	"/chat/completions",
	"/completions",
	"/messages",
	":generateContent",
	":streamGenerateContent",
	"/converse",
	"/converse-stream",
	"/api/chat",
	"/api/generate",
	"/responses",
	"/backend-api/codex/responses",
}

// KnownSafeDomains are package-registry / telemetry hosts that we never
// want to intercept even if a misconfigured client points them at us.
var KnownSafeDomains = []string{
	"github.com",
	"raw.githubusercontent.com",
	"codeload.github.com",
	"objects.githubusercontent.com",
	"registry.npmjs.org",
	"npmjs.org",
	"yarnpkg.com",
	"pypi.org",
	"files.pythonhosted.org",
	"crates.io",
	"rubygems.org",
	"sentry.io",
	"datadoghq.com",
	"segment.io",
	"segment.com",
}

// BodyShape enumerates the LLM body shapes Layer 1 can recognize.
// Keep identical to the TS LLMBodyShape union.
type BodyShape string

const (
	BodyShapeNone     BodyShape = "none"
	BodyShapeMessages BodyShape = "messages"
	BodyShapePrompt   BodyShape = "prompt"
	BodyShapeInput    BodyShape = "input"
	BodyShapeContents BodyShape = "contents"
)

// isLLMShapedBody inspects up to the first 64 KiB of a request body and
// returns the matching shape or BodyShapeNone when it cannot classify.
// Returns (shape, true) when at least one LLM key was found, otherwise
// (BodyShapeNone, false). Never parses beyond the cap to prevent a
// hostile payload from bloating heap just to foil detection.
func isLLMShapedBody(b []byte) (BodyShape, bool) {
	if len(b) == 0 {
		return BodyShapeNone, false
	}
	const cap = 64 * 1024
	if len(b) > cap {
		b = b[:cap]
	}
	// Cheap shape peek first — only the first JSON object's top-level
	// keys matter. bytes.TrimSpace strips any leading whitespace so a
	// pretty-printed body with a leading newline still parses.
	if trimmed := bytes.TrimSpace(b); len(trimmed) == 0 || trimmed[0] != '{' {
		return BodyShapeNone, false
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		// Truncated payloads are common (streaming or a 64 KiB slice
		// that split mid-string). Fall back to a key-substring probe
		// so we still recognize obvious LLM payloads.
		probe := fallbackShapeProbe(b)
		return probe, probe != BodyShapeNone
	}

	// Check in provider-priority order: messages (OpenAI/Anthropic),
	// contents (Gemini), input (Responses API), inputs (legacy),
	// prompt (legacy / completion).
	if raw, ok := top["messages"]; ok && shapeIsArray(raw) {
		return BodyShapeMessages, true
	}
	if raw, ok := top["contents"]; ok && shapeIsArray(raw) {
		return BodyShapeContents, true
	}
	if raw, ok := top["input"]; ok && (shapeIsString(raw) || shapeIsArray(raw)) {
		return BodyShapeInput, true
	}
	if raw, ok := top["inputs"]; ok && shapeIsArray(raw) {
		return BodyShapeInput, true
	}
	if raw, ok := top["prompt"]; ok && shapeIsString(raw) {
		return BodyShapePrompt, true
	}
	return BodyShapeNone, false
}

func shapeIsArray(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '['
}

func shapeIsString(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '"'
}

// fallbackShapeProbe runs when the body failed to JSON-parse (usually
// because it was truncated). A cheap substring probe on the first 4
// KiB is still useful: a body that starts with `{"messages":[...` will
// be recognized even when we never see the closing brace.
func fallbackShapeProbe(b []byte) BodyShape {
	snippet := b
	if len(snippet) > 4096 {
		snippet = snippet[:4096]
	}
	s := string(snippet)
	if strings.Contains(s, `"messages"`) && strings.Contains(s, "[") {
		return BodyShapeMessages
	}
	if strings.Contains(s, `"contents"`) && strings.Contains(s, "[") {
		return BodyShapeContents
	}
	if strings.Contains(s, `"input"`) || strings.Contains(s, `"inputs"`) {
		return BodyShapeInput
	}
	if strings.Contains(s, `"prompt"`) {
		return BodyShapePrompt
	}
	return BodyShapeNone
}

// isLLMPathSuffix reports whether the URL path looks like an LLM endpoint.
func isLLMPathSuffix(rawURL string) bool {
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		path = u.Path
	}
	for _, s := range LLMPathSuffixes {
		if strings.HasSuffix(path, s) || strings.Contains(path, s) {
			return true
		}
	}
	return false
}

// isKnownSafeDomain returns true when the hostname is in KnownSafeDomains.
func isKnownSafeDomain(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	for _, d := range KnownSafeDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// isPrivateHost returns true when host (a bare IP literal or
// host:port form) resolves to an RFC 1918 / RFC 4193 / loopback /
// link-local address — the SSRF short list. Accepted inputs:
//   - bare IP literal:  "10.0.0.1", "::1", "fe80::1%eth0"
//   - host:port form:   "10.0.0.1:8080"
//   - bracketed v6:     "[::1]:8080"
//
// NOTE: a separate isPrivateIP(net.IP) exists in webhook.go for the
// webhook SSRF allowlist. This function is the URL-string flavour.
func isPrivateHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	// Strip port / brackets if present.
	if strings.HasPrefix(h, "[") {
		if idx := strings.Index(h, "]"); idx > 0 {
			h = h[1:idx]
		}
	} else if h2, _, err := net.SplitHostPort(h); err == nil {
		h = h2
	}
	ip := net.ParseIP(h)
	if ip != nil {
		return isPrivateIP(ip)
	}
	// Hostname — resolve and check all returned IPs to prevent DNS rebinding.
	addrs, err := net.LookupHost(h)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if resolved := net.ParseIP(addr); resolved != nil && isPrivateIP(resolved) {
			return true
		}
	}
	return false
}
