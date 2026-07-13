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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// hydratingTestConnector is a minimal connector.Connector used only to
// drive the connector-hydrated branch of handleChatCompletion's SSRF
// guards. Native-binary connectors (codex, zeptoclaw) follow this
// shape: agents have no fetch interceptor, the request arrives
// without X-DC-Target-URL / X-AI-Auth, and Route returns the upstream
// from the captured config snapshot. Pre-fix handleChatCompletion
// used to run the SSRF guards BEFORE Route, so any private/IMDS/CGNAT
// upstream returned here would slip past the structured 400/403
// + labeled egress event and only get caught at dial time by
// ssrfSafeDialContext (returning an opaque "ssrf-dial: ... private
// host" error to the caller). This connector lets us assert the
// fixed order: Route runs first, the SSRF guards see the hydrated
// URL, and the call is rejected with the same status / message /
// audit trail as the X-DC-Target-URL case.
type hydratingTestConnector struct {
	upstream string
	apiKey   string
}

func (c *hydratingTestConnector) Name() string        { return "hydrating-test" }
func (c *hydratingTestConnector) Description() string { return "test-only" }
func (c *hydratingTestConnector) ToolInspectionMode() connector.ToolInspectionMode {
	return connector.ToolModeBoth
}
func (c *hydratingTestConnector) SubprocessPolicy() connector.SubprocessPolicy {
	return connector.SubprocessNone
}
func (c *hydratingTestConnector) Authenticate(_ *http.Request) bool { return true }
func (c *hydratingTestConnector) Setup(_ context.Context, _ connector.SetupOpts) error {
	return nil
}
func (c *hydratingTestConnector) Teardown(_ context.Context, _ connector.SetupOpts) error {
	return nil
}
func (c *hydratingTestConnector) VerifyClean(_ connector.SetupOpts) error { return nil }
func (c *hydratingTestConnector) SetCredentials(_, _ string)              {}
func (c *hydratingTestConnector) Route(_ *http.Request, _ []byte) (*connector.ConnectorSignals, error) {
	return &connector.ConnectorSignals{
		RawUpstream: c.upstream,
		RawAPIKey:   c.apiKey,
	}, nil
}

// TestHandleChatCompletion_HydratedTargetURL_HitsSSRFGuards is the
// regression assertion for the order-of-operations fix in
// handleChatCompletion. The exact scenario it covers:
//
//   - A Codex / ZeptoClaw native-binary agent makes a chat-completion
//     request through the guardrail proxy.
//   - The agent has no fetch interceptor, so X-DC-Target-URL is empty.
//   - The configured connector's snapshot resolves the upstream to a
//     private/IMDS/CGNAT/IPv6-ULA address (operator misconfiguration,
//     supply-chain compromise of a connector binary, or a future
//     connector that hosts a local model on 100.64.x).
//
// Pre-fix:
//
//	req.TargetURL = "" (no header)
//	  → SSRF guards run on "" → no-op (skipped)
//	  → hydrateConnectorSignals fills req.TargetURL = "http://169.254.169.254/..."
//	  → request reaches Bifrost → ssrfSafeDialContext refuses dial
//	  → caller sees opaque dial-failure; audit pipeline gets no
//	    "chat / block / private-ip" breadcrumb.
//
// Post-fix (this test): hydrateConnectorSignals runs first, the
// guards see the hydrated URL, and the request is rejected with HTTP
// 403 + the structured "target host resolves to a private address"
// response — identical to the X-DC-Target-URL path. The test
// enumerates every newly-reserved address class (RFC 1918, loopback,
// IMDS, ECS task metadata, CGNAT, IPv6 ULA) so a future regression
// that re-orders these blocks fails loudly per address family.
func TestHandleChatCompletion_HydratedTargetURL_HitsSSRFGuards(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	// newTestProxy enables passthroughAllowPrivateForTest so legacy
	// httptest fixtures keep working. Disable it so the production
	// SSRF guard runs against our hydrated upstream.
	passthroughAllowPrivateForTest = false
	t.Cleanup(func() { passthroughAllowPrivateForTest = true })

	body := mustJSON(t, map[string]interface{}{
		"model":    "openai/gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
	})

	cases := []struct {
		name     string
		upstream string
	}{
		{"loopback", "http://127.0.0.1:8080"},
		{"rfc1918_10", "http://10.0.0.5:8080"},
		{"rfc1918_172", "http://172.16.0.5:8080"},
		{"rfc1918_192", "http://192.168.1.5:8080"},
		{"imds_v1", "http://169.254.169.254"},
		{"ecs_task_metadata", "http://169.254.170.2"},
		{"cgnat_tailscale", "http://100.64.0.5:11434"},
		{"ipv6_ula", "http://[fd00::1]:8080"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Install a fresh connector per subtest so cross-test
			// contamination via a shared snapshot is impossible.
			proxy.connector = &hydratingTestConnector{
				upstream: tc.upstream,
				apiKey:   "sk-test-fake",
			}
			t.Cleanup(func() { proxy.connector = nil })

			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			// Critical: NO X-DC-Target-URL header. The hydrated
			// path is the ONLY way TargetURL becomes non-empty.
			req.RemoteAddr = "127.0.0.1:12345"
			rec := httptest.NewRecorder()

			proxy.handleChatCompletion(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for hydrated %s upstream %q, got %d: %s",
					tc.name, tc.upstream, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "private address") {
				t.Errorf("response body should mention private address, got: %s", rec.Body.String())
			}
		})
	}
}

// TestHandleChatCompletion_HydratedTargetURL_RejectsUserinfo proves
// the userinfo guard also runs against the hydrated path (not just
// the X-DC-Target-URL header path). A compromised connector binary
// returning "https://attacker:password@api.openai.com" would
// otherwise smuggle the userinfo into the upstream Authorization
// header.
func TestHandleChatCompletion_HydratedTargetURL_RejectsUserinfo(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	passthroughAllowPrivateForTest = false
	t.Cleanup(func() { passthroughAllowPrivateForTest = true })

	proxy.connector = &hydratingTestConnector{
		upstream: "https://attacker:password@api.openai.com",
		apiKey:   "sk-test-fake",
	}
	t.Cleanup(func() { proxy.connector = nil })

	body := mustJSON(t, map[string]interface{}{
		"model":    "openai/gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for userinfo in hydrated upstream, got %d: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "userinfo") {
		t.Errorf("response body should mention userinfo, got: %s", rec.Body.String())
	}
}

// TestHandleChatCompletion_HydratedTargetURL_RejectsNonHTTPScheme
// proves the scheme guard also runs against the hydrated path.
func TestHandleChatCompletion_HydratedTargetURL_RejectsNonHTTPScheme(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	passthroughAllowPrivateForTest = false
	t.Cleanup(func() { passthroughAllowPrivateForTest = true })

	proxy.connector = &hydratingTestConnector{
		upstream: "file:///etc/passwd",
		apiKey:   "sk-test-fake",
	}
	t.Cleanup(func() { proxy.connector = nil })

	body := mustJSON(t, map[string]interface{}{
		"model":    "openai/gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-http scheme in hydrated upstream, got %d: %s",
			rec.Code, rec.Body.String())
	}
}
