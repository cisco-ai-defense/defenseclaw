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
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestMatchProviderDomain_BedrockWildcard pins the new
// matchWildcardDomain behaviour. The DeepSec audit found that the
// previous trailing-dot prefix syntax (domains: ["bedrock-runtime."])
// matched "bedrock-runtime.evil.example", letting an attacker spoof a
// known-provider host and bypass the SSRF private-host gate. The
// replacement pattern "bedrock-runtime.*.amazonaws.com" must:
//
//   - match real Bedrock regional hosts
//   - reject any prefix-only spoof
//   - reject any suffix-only spoof
//   - reject hosts that smuggle additional labels through the wildcard
//     (e.g. "bedrock-runtime.attacker.amazonaws.com.evil.com")
func TestMatchProviderDomain_BedrockWildcard(t *testing.T) {
	const pattern = "bedrock-runtime.*.amazonaws.com"
	cases := []struct {
		host string
		want bool
	}{
		{"bedrock-runtime.us-east-1.amazonaws.com", true},
		{"bedrock-runtime.eu-west-2.amazonaws.com", true},
		{"bedrock-runtime.ap-southeast-1.amazonaws.com", true},
		// DeepSec-flagged spoofs — every one of these matched the
		// legacy "bedrock-runtime." prefix entry.
		{"bedrock-runtime.evil.example", false},
		{"bedrock-runtime.attacker.amazonaws.com.evil.com", false},
		{"bedrock-runtime..amazonaws.com", false},
		{"bedrock-runtime.us-east-1.evil.com", false},
		{"evil-bedrock-runtime.us-east-1.amazonaws.com", false},
		// Multi-label middle is NOT one DNS label, so refused.
		{"bedrock-runtime.foo.bar.amazonaws.com", false},
		{"bedrock-runtime.amazonaws.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			got := matchProviderDomain(tc.host, "/v1/x", pattern)
			if got != tc.want {
				t.Errorf("matchProviderDomain(%q, %q) = %v, want %v",
					tc.host, pattern, got, tc.want)
			}
		})
	}
}

// TestMatchProviderDomain_TrailingDotRefused: the legacy prefix-only
// syntax (domains: ["bedrock-runtime."]) is no longer honoured. Any
// custom-providers.json overlay that still uses the legacy form
// MUST be migrated to a wildcard pattern; otherwise its providers
// will silently disappear from the allow-list.
func TestMatchProviderDomain_TrailingDotRefused(t *testing.T) {
	if matchProviderDomain("bedrock-runtime.us-east-1.amazonaws.com", "/x", "bedrock-runtime.") {
		t.Errorf("legacy trailing-dot prefix should no longer match (DeepSec)")
	}
}

// TestMatchProviderDomain_ExactAndSubdomain confirms the unchanged
// default branch still handles the common entries (api.openai.com,
// api.anthropic.com, etc.) without false positives on suffix-bypass
// hostnames.
func TestMatchProviderDomain_ExactAndSubdomain(t *testing.T) {
	tests := []struct {
		host    string
		domain  string
		want    bool
		comment string
	}{
		{"api.openai.com", "api.openai.com", true, "exact"},
		{"staging.api.openai.com", "api.openai.com", true, "subdomain"},
		{"api.openai.com.evil.example", "api.openai.com", false, "suffix-spoof"},
		{"notapi.openai.com", "api.openai.com", false, "embed-spoof"},
	}
	for _, tt := range tests {
		t.Run(tt.comment, func(t *testing.T) {
			if got := matchProviderDomain(tt.host, "/x", tt.domain); got != tt.want {
				t.Errorf("matchProviderDomain(%q,%q)=%v, want %v",
					tt.host, tt.domain, got, tt.want)
			}
		})
	}
}

// TestHandlePassthrough_RejectsUserinfo confirms that an attacker who
// can influence X-DC-Target-URL cannot smuggle credentials through a
// userinfo segment. Even if api.openai.com is on the allow-list,
// "https://attacker:password@api.openai.com" must be refused -- the
// userinfo half escapes downstream into the upstream Authorization
// header, leaking the attacker-supplied credential.
func TestHandlePassthrough_RejectsUserinfo(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	body := mustJSON(t, map[string]interface{}{
		"model":    "claude-opus-4-5",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://attacker:password@api.anthropic.com")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handlePassthrough(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for userinfo URL, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "userinfo") {
		t.Errorf("response should mention userinfo: %s", rec.Body.String())
	}
}

// TestHandleChatCompletion_RejectsUserinfo confirms the chat
// completion route applies the same userinfo-rejection guard as
// handlePassthrough. Pre-fix this route silently forwarded the
// userinfo segment to Bifrost (which uses its own HTTP stack and
// would have leaked the credential into the upstream Authorization
// header).
func TestHandleChatCompletion_RejectsUserinfo(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	body := mustJSON(t, map[string]interface{}{
		"model":    "openai/gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://attacker:password@api.openai.com")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for userinfo URL on chat completion, got %d: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "userinfo") {
		t.Errorf("response should mention userinfo: %s", rec.Body.String())
	}
}

// TestHandleChatCompletion_RejectsNonHTTPScheme pins the scheme
// guard parity with passthrough.
func TestHandleChatCompletion_RejectsNonHTTPScheme(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	body := mustJSON(t, map[string]interface{}{
		"model":    "openai/gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "file:///etc/passwd")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-http(s) scheme on chat completion, got %d: %s",
			rec.Code, rec.Body.String())
	}
}

// TestHandleChatCompletion_RejectsPrivateHost pins the
// private-host guard parity with passthrough. Since
// `newTestProxy` sets `passthroughAllowPrivateForTest = true` for
// legacy fixtures, we must explicitly turn it back off so the
// real production guard runs.
func TestHandleChatCompletion_RejectsPrivateHost(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	// Override the test-bypass enabled by newTestProxy so we exercise
	// the production guard. Restore after the test.
	passthroughAllowPrivateForTest = false
	t.Cleanup(func() { passthroughAllowPrivateForTest = true })

	body := mustJSON(t, map[string]interface{}{
		"model":    "openai/gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
	})
	cases := []struct {
		name   string
		target string
	}{
		{"loopback", "http://127.0.0.1:8080/v1/chat/completions"},
		{"imdsv2", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
		{"ecs_metadata", "http://169.254.170.2/v2/credentials/abc"},
		{"private_rfc1918", "http://10.0.0.1:8080/v1/chat/completions"},
		{"cgnat", "http://100.64.0.1:8080/v1/chat/completions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DC-Target-URL", tc.target)
			req.RemoteAddr = "127.0.0.1:12345"
			rec := httptest.NewRecorder()
			proxy.handleChatCompletion(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("expected 403 for %s (%s), got %d: %s",
					tc.name, tc.target, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestSSRFSafeDialContext_RefusesPrivateIP exercises the
// providerHTTPClient transport guard directly. Even if a known
// provider's hostname were CNAME'd or DNS-rebound between the
// application-level isPrivateHost check and the actual TCP dial, the
// transport must refuse to connect to a private IP, link-local IMDS,
// CGNAT, or IPv6 ULA address.
func TestSSRFSafeDialContext_RefusesPrivateIP(t *testing.T) {
	cases := []string{
		"127.0.0.1:443",
		"10.0.0.1:443",
		"172.16.0.1:443",
		"192.168.1.1:443",
		"169.254.169.254:80", // EC2 IMDSv2
		"169.254.170.2:80",   // ECS task metadata
		"100.64.0.1:443",     // RFC 6598 CGNAT
		"[::1]:443",
		"[fd00::1]:443",
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			conn, err := ssrfSafeDialContext(t.Context(), "tcp", addr)
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatalf("expected refusal of %s, got nil error", addr)
			}
			if !strings.Contains(err.Error(), "ssrf") {
				t.Errorf("expected ssrf-prefixed error, got %v", err)
			}
		})
	}
}

// TestSSRFSafeCheckRedirect_BlocksPrivateAndOddSchemes confirms the
// CheckRedirect hook on providerHTTPClient refuses redirects to
// private hosts and to non-http(s) schemes. The Go default client
// would otherwise follow the Location header without re-validating
// the destination.
func TestSSRFSafeCheckRedirect_BlocksPrivateAndOddSchemes(t *testing.T) {
	mk := func(s string) *http.Request {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("parse %s: %v", s, err)
		}
		return &http.Request{URL: u}
	}
	cases := []struct {
		name string
		req  *http.Request
		want bool // expect error?
	}{
		{"public_host_ok", mk("https://api.openai.com/v1/x"), false},
		{"loopback_blocked", mk("http://127.0.0.1/x"), true},
		{"link_local_blocked", mk("http://169.254.169.254/x"), true},
		{"file_scheme_blocked", mk("file:///etc/passwd"), true},
		{"ftp_scheme_blocked", mk("ftp://evil.com/x"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ssrfSafeCheckRedirect(tc.req, nil)
			if (err != nil) != tc.want {
				t.Errorf("got err=%v, wantErr=%v", err, tc.want)
			}
		})
	}
}

// TestIsUnsafeIP exhaustively pins the address class refusal list so
// future changes to net.IP semantics (or a refactor of
// ssrfSafeDialContext) cannot silently weaken it.
func TestIsUnsafeIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // EC2/Azure/GCP IMDS
		{"169.254.170.2", true},   // ECS task metadata
		{"100.64.0.1", true},      // RFC 6598 CGNAT (newly added in extraReservedNets)
		{"100.127.255.255", true}, // CGNAT upper bound
		{"0.0.0.0", true},
		{"::1", true},
		{"fd00::1", true}, // IPv6 ULA
		{"fdff::1", true}, // IPv6 ULA upper subset
		{"::", true},
		{"1.1.1.1", false},
		{"8.8.8.8", false},
		{"100.63.255.255", false},       // just below CGNAT range
		{"100.128.0.0", false},          // just above CGNAT range
		{"172.32.0.1", false},           // outside the 172.16/12 private range
		{"2001:4860:4860::8888", false}, // public IPv6 (Google DNS)
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("parse %q failed", tt.ip)
			}
			if got := isUnsafeIP(ip); got != tt.want {
				t.Errorf("isUnsafeIP(%s)=%v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
