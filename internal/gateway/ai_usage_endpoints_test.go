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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// aiUsageTestServer is the canonical fixture for the new endpoints:
// returns an APIServer wired with a token, an in-memory audit
// store/logger, and (when enabled) a discovery service backed by a
// throwaway temp dir so each test is hermetic.
//
// The boolean controls whether the discovery service is attached.
// Endpoints that need to behave differently when discovery is
// disabled use the (false) variant.
func aiUsageTestServer(t *testing.T, withDiscovery bool) *APIServer {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Gateway.Token = "test-token"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	if withDiscovery {
		api.SetAIDiscoveryService(inventory.NewContinuousDiscoveryServiceWithOptions(
			inventory.AIDiscoveryOptions{Enabled: true, DataDir: t.TempDir(), EmitOTel: false},
			nil,
			nil,
			nil,
		))
	}
	return api
}

// withSidecarHeaders adds the headers the sidecar's auth + CSRF
// middleware expects on a state-changing POST. Tests use this to
// build requests that round-trip the full middleware stack and
// catch wire-contract regressions like the validate Content-Type
// bug (F1 in the dedup-evidence-confidence review).
func withSidecarHeaders(req *http.Request) *http.Request {
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("X-DefenseClaw-Client", "python-cli")
	if req.Method == http.MethodPost && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// ---------- /api/v1/ai-usage/components -----------------------------------

func TestHandleAIUsageComponents_DisabledReturnsEmpty(t *testing.T) {
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ai-usage/components", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageComponents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["enabled"] != false {
		t.Errorf("enabled=%v want false", resp["enabled"])
	}
	comps, _ := resp["components"].([]any)
	if len(comps) != 0 {
		t.Errorf("components=%d want 0 when discovery disabled", len(comps))
	}
}

func TestHandleAIUsageComponents_RejectsNonGET(t *testing.T) {
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai-usage/components", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageComponents(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", w.Code)
	}
}

// ---------- /api/v1/ai-usage/components/{eco}/{name}/{leaf} ---------------

// TestParseComponentPath pins the routing contract for the
// locations + history endpoints. The handler trusts this helper to
// (a) reject anything that isn't /<prefix><eco>/<name><suffix>, and
// (b) cap segment lengths so a hostile client can't waste CPU on
// LOWER() comparisons over megabytes of name.
func TestParseComponentPath(t *testing.T) {
	prefix := "/api/v1/ai-usage/components/"
	cases := []struct {
		name     string
		path     string
		suffix   string
		wantOK   bool
		wantEco  string
		wantName string
	}{
		{
			name: "happy locations", path: prefix + "pypi/openai/locations",
			suffix: "/locations", wantOK: true, wantEco: "pypi", wantName: "openai",
		},
		{
			name: "scoped npm name with literal / is rejected",
			// Real callers MUST percent-encode the `/` inside a
			// scoped npm name; a literal `/` arrives as a third
			// segment and is unambiguously ambiguous.
			path:   prefix + "npm/@anthropic-ai/sdk/history",
			suffix: "/history", wantOK: false,
		},
		{
			name: "scoped npm name with %2F round-trips",
			// Production CLI calls quote(name, safe='') so the
			// scoped slash arrives as %2F. EscapedPath preserves
			// it and PathUnescape restores the literal name so
			// the SQL query hits the right row.
			path:   prefix + "npm/%40anthropic-ai%2Fsdk/history",
			suffix: "/history", wantOK: true,
			wantEco: "npm", wantName: "@anthropic-ai/sdk",
		},
		{
			name: "encoded space and other reserved chars decode",
			// Belt-and-braces for the _gateway test that exercises
			// `quote("npm", "@org/foo bar")` from the Python side.
			path:   prefix + "npm/%40org%2Ffoo%20bar/locations",
			suffix: "/locations", wantOK: true,
			wantEco: "npm", wantName: "@org/foo bar",
		},
		{
			name: "malformed percent-escape rejected",
			// Defense-in-depth: a half-typed escape (`%2`) MUST
			// fail closed; otherwise PathUnescape returns an
			// error and we'd accidentally feed a partial string
			// into the SQL store.
			path:   prefix + "npm/%2/locations",
			suffix: "/locations", wantOK: false,
		},
		{
			name: "missing suffix", path: prefix + "pypi/openai",
			suffix: "/locations", wantOK: false,
		},
		{
			name: "wrong prefix", path: "/api/v1/other/pypi/openai/locations",
			suffix: "/locations", wantOK: false,
		},
		{
			name: "empty ecosystem", path: prefix + "/openai/locations",
			suffix: "/locations", wantOK: false,
		},
		{
			name: "empty name", path: prefix + "pypi//locations",
			suffix: "/locations", wantOK: false,
		},
		{
			name:   "ecosystem too long",
			path:   prefix + strings.Repeat("a", 257) + "/openai/locations",
			suffix: "/locations", wantOK: false,
		},
		{
			name:   "name too long",
			path:   prefix + "pypi/" + strings.Repeat("a", 257) + "/locations",
			suffix: "/locations", wantOK: false,
		},
		{
			name:   "ecosystem at length cap accepted",
			path:   prefix + strings.Repeat("a", 256) + "/openai/locations",
			suffix: "/locations", wantOK: true,
			wantEco: strings.Repeat("a", 256), wantName: "openai",
		},
		{
			name: "literal slash inside ecosystem segment rejected",
			// The handler now uses URL.EscapedPath() so percent-
			// encoded `/` round-trips, but a *literal* slash in a
			// real route still produces three segments and we
			// continue to reject those (otherwise an attacker
			// could probe arbitrary subpaths under the prefix).
			path:   prefix + "py/pi/openai/locations",
			suffix: "/locations", wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eco, name, ok := parseComponentPath(tc.path, prefix, tc.suffix)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v (eco=%q name=%q)", ok, tc.wantOK, eco, name)
			}
			if ok && (eco != tc.wantEco || name != tc.wantName) {
				t.Errorf("got (%q,%q) want (%q,%q)", eco, name, tc.wantEco, tc.wantName)
			}
		})
	}
}

func TestHandleAIUsageComponentLocations_DisabledReturnsEmpty(t *testing.T) {
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/components/pypi/openai/locations", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageComponentLocations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["enabled"] != false {
		t.Errorf("enabled=%v want false", resp["enabled"])
	}
}

func TestHandleAIUsageComponentLocations_BadPathReturns400(t *testing.T) {
	api := aiUsageTestServer(t, true)
	// Hit an enabled service but with a path that fails parseComponentPath
	// (no suffix). Confirms the handler maps a routing miss to 400 not 500.
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/components/pypi/openai", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageComponentLocations(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
}

// TestHandleAIUsageComponentLocations_ScopedNpmNameRoundTrips verifies
// that a real-world request from the CLI for an `@anthropic-ai/sdk`
// style scoped npm name does not 400. Pre-fix this returned the
// generic "expected ..." 400 because the handler used URL.Path (which
// net/http silently decodes %2F to "/") and parseComponentPath then
// saw three segments. Pin the wire contract here so a regression
// surfaces in CI rather than the next time an operator runs
// `defenseclaw agent components show @anthropic-ai/sdk --ecosystem npm`.
func TestHandleAIUsageComponentLocations_ScopedNpmNameRoundTrips(t *testing.T) {
	api := aiUsageTestServer(t, true)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/components/npm/%40anthropic-ai%2Fsdk/locations", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageComponentLocations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The store has nothing recorded so locations is empty; what
	// we care about is that the ecosystem/name are echoed back
	// fully decoded so the caller can render them in a table.
	if resp["ecosystem"] != "npm" {
		t.Errorf("ecosystem=%v want npm", resp["ecosystem"])
	}
	if resp["name"] != "@anthropic-ai/sdk" {
		t.Errorf("name=%v want @anthropic-ai/sdk", resp["name"])
	}
}

// TestHandleAIUsageComponentHistory_ScopedNpmNameRoundTrips mirrors
// the locations smoke for the /history leaf so both endpoints stay
// in lockstep when somebody refactors parseComponentPath.
func TestHandleAIUsageComponentHistory_ScopedNpmNameRoundTrips(t *testing.T) {
	api := aiUsageTestServer(t, true)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/components/npm/%40anthropic-ai%2Fsdk/history", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageComponentHistory(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["ecosystem"] != "npm" {
		t.Errorf("ecosystem=%v want npm", resp["ecosystem"])
	}
	if resp["name"] != "@anthropic-ai/sdk" {
		t.Errorf("name=%v want @anthropic-ai/sdk", resp["name"])
	}
}

func TestHandleAIUsageComponentLocations_RejectsNonGET(t *testing.T) {
	api := aiUsageTestServer(t, true)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/ai-usage/components/pypi/openai/locations", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageComponentLocations(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", w.Code)
	}
}

func TestHandleAIUsageComponentHistory_DisabledReturnsEmpty(t *testing.T) {
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/components/pypi/openai/history", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageComponentHistory(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["enabled"] != false {
		t.Errorf("enabled=%v want false", resp["enabled"])
	}
}

func TestHandleAIUsageComponentHistory_BadPathReturns400(t *testing.T) {
	api := aiUsageTestServer(t, true)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/components/pypi/openai/locations", nil) // wrong leaf
	w := httptest.NewRecorder()

	api.handleAIUsageComponentHistory(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
}

// ---------- /api/v1/ai-usage/confidence/policy ----------------------------

func TestHandleAIUsageConfidencePolicy_DefaultEvenWhenDisabled(t *testing.T) {
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/confidence/policy?source=default", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["source"] != "default" {
		t.Errorf("source=%v want default", resp["source"])
	}
	if resp["enabled"] != false {
		t.Errorf("enabled=%v want false (no discovery service attached)", resp["enabled"])
	}
	if _, ok := resp["policy"].(map[string]any); !ok {
		t.Fatalf("policy field missing or wrong type: %v", resp["policy"])
	}
}

func TestHandleAIUsageConfidencePolicy_MergedFallsBackToDefaultWhenDisabled(t *testing.T) {
	// Without an attached discovery service, source=merged still
	// returns the default so an operator can inspect the shipping
	// policy before opting in to discovery. The response carries
	// source="default" (not "merged") so the caller can tell.
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/confidence/policy", nil) // no source → merged
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["source"] != "default" {
		t.Errorf("source=%v want default (fallback when discovery disabled)", resp["source"])
	}
}

func TestHandleAIUsageConfidencePolicy_RejectsBadSource(t *testing.T) {
	api := aiUsageTestServer(t, true)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/confidence/policy?source=bogus", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestHandleAIUsageConfidencePolicy_RejectsNonGET(t *testing.T) {
	api := aiUsageTestServer(t, true)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/ai-usage/confidence/policy", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicy(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", w.Code)
	}
}

// ---------- /api/v1/ai-usage/confidence/policy/validate -------------------

func TestHandleAIUsageConfidencePolicyValidate_AcceptsValidJSONEnvelope(t *testing.T) {
	// Empty YAML = "use the default", which is valid by definition.
	body, err := json.Marshal(map[string]any{"yaml": ""})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/ai-usage/confidence/policy/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicyValidate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["valid"] != true {
		t.Errorf("valid=%v want true; resp=%v", resp["valid"], resp)
	}
}

// TestHandleAIUsageConfidencePolicyValidate_PolicyAliasAccepted pins
// the documented alias: the wire envelope accepts BOTH `yaml` and
// `policy` as the key holding the raw YAML. Drift between operator
// scripts and the docs would silently fail without this test.
func TestHandleAIUsageConfidencePolicyValidate_PolicyAliasAccepted(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"policy": ""})
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/ai-usage/confidence/policy/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicyValidate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["valid"] != true {
		t.Errorf("valid=%v want true (policy alias)", resp["valid"])
	}
}

func TestHandleAIUsageConfidencePolicyValidate_RejectsBadYAML(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"yaml": "this: is: not: valid: yaml: ::::\n"})
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/ai-usage/confidence/policy/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicyValidate(w, req)

	// Always 200 OK; the failure is in the body so `jq -e '.valid'`
	// is the operator's exit gate.
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["valid"] != false {
		t.Errorf("valid=%v want false", resp["valid"])
	}
	if msg, _ := resp["error"].(string); msg == "" {
		t.Error("error field empty for invalid YAML")
	}
}

func TestHandleAIUsageConfidencePolicyValidate_RejectsEmptyBody(t *testing.T) {
	// An empty body is not valid JSON; the handler must surface a
	// helpful error rather than returning {valid:true} (which would
	// mislead the operator into thinking their empty file was OK).
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/ai-usage/confidence/policy/validate", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicyValidate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", w.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["valid"] != false {
		t.Errorf("valid=%v want false on empty body", resp["valid"])
	}
}

func TestHandleAIUsageConfidencePolicyValidate_RejectsNonJSONBody(t *testing.T) {
	// Raw YAML body (no envelope) is the exact bug the F1 review
	// caught: pre-fix the client sent application/x-yaml, the gate
	// 415'd it, and even if the gate had let it through the handler
	// would have parsed garbage. Pin the new "JSON envelope only"
	// contract here.
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/ai-usage/confidence/policy/validate",
		strings.NewReader("version: 1\n"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicyValidate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["valid"] != false {
		t.Errorf("valid=%v want false on non-JSON body", resp["valid"])
	}
}

func TestHandleAIUsageConfidencePolicyValidate_RejectsOversizeBody(t *testing.T) {
	// 65 KiB > 64 KiB cap → 413. The cap is doubly-enforced
	// (LimitReader + post-read length check) to handle any reader
	// quirks; this exercises the post-read branch.
	huge := strings.Repeat("a", confidencePolicyMaxRequestBytes+10)
	body, _ := json.Marshal(map[string]any{"yaml": huge})
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/ai-usage/confidence/policy/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicyValidate(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413; body=%s", w.Code, w.Body.String())
	}
}

func TestHandleAIUsageConfidencePolicyValidate_RejectsNonPOST(t *testing.T) {
	api := aiUsageTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/confidence/policy/validate", nil)
	w := httptest.NewRecorder()

	api.handleAIUsageConfidencePolicyValidate(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", w.Code)
	}
}

// ---------- middleware integration ----------------------------------------

// TestValidateEndpoint_PassesCSRFGate is the regression test for F1.
// Pre-fix the CLI sent Content-Type: application/x-yaml which
// apiCSRFProtect rejects with 415. Pin the new contract: the
// validate endpoint must be reachable from the same JSON-only POST
// path every other CLI command uses.
func TestValidateEndpoint_PassesCSRFGate(t *testing.T) {
	api := aiUsageTestServer(t, false)
	handler := api.tokenAuth(api.apiCSRFProtect(http.HandlerFunc(api.handleAIUsageConfidencePolicyValidate)))

	body, _ := json.Marshal(map[string]any{"yaml": ""})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/ai-usage/confidence/policy/validate", bytes.NewReader(body))
	req = withSidecarHeaders(req)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 through full middleware stack; body=%s",
			w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["valid"] != true {
		t.Errorf("valid=%v want true; resp=%v", resp["valid"], resp)
	}
}

// TestValidateEndpoint_YAMLContentTypeRejected pins the matching
// negative path: posting raw YAML with Content-Type:
// application/x-yaml (the pre-fix CLI behavior) MUST be 415'd by
// the CSRF gate. If this test ever passes 200, the gate has
// regressed and all of /confidence/policy/validate is exposed to
// CSRF.
func TestValidateEndpoint_YAMLContentTypeRejected(t *testing.T) {
	api := aiUsageTestServer(t, false)
	handler := api.tokenAuth(api.apiCSRFProtect(http.HandlerFunc(api.handleAIUsageConfidencePolicyValidate)))

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/ai-usage/confidence/policy/validate",
		strings.NewReader("version: 1\n"))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("X-DefenseClaw-Client", "python-cli")
	req.Header.Set("Content-Type", "application/x-yaml")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d want 415 (CSRF gate must reject non-JSON); body=%s",
			w.Code, w.Body.String())
	}
}

// ---------- rollupComponents data fidelity --------------------------------

// TestRollupComponents_VendorAndFrameworkPickFirstNonEmpty pins the
// fix for F6/F7 (review pass 2): when the arbitrarily-ordered
// signal group has [0] missing the field but [1] supplying it, the
// rollup MUST surface the [1] value rather than blanking the
// column. Pre-fix the rollup did `group[0].Vendor` / `Framework`
// unconditionally so vendor/framework cells were stably blank for
// any component whose first-iterated signal lacked them.
func TestRollupComponents_VendorAndFrameworkPickFirstNonEmpty(t *testing.T) {
	now := time.Now().UTC()
	signals := []inventory.AISignal{
		{
			Component: &inventory.AIComponent{Ecosystem: "pypi", Name: "openai", Framework: ""},
			Vendor:    "",
			LastSeen:  now,
		},
		{
			Component: &inventory.AIComponent{Ecosystem: "pypi", Name: "openai", Framework: "agents"},
			Vendor:    "openai-inc",
			LastSeen:  now,
		},
	}
	out := rollupComponents(signals, inventory.ConfidenceParams{}, false)
	if len(out) != 1 {
		t.Fatalf("rollup len=%d want 1", len(out))
	}
	if out[0].Vendor != "openai-inc" {
		t.Errorf("vendor=%q want openai-inc (first non-empty across group)", out[0].Vendor)
	}
	if out[0].Framework != "agents" {
		t.Errorf("framework=%q want agents (first non-empty across group)", out[0].Framework)
	}
}

// TestRollupComponents_LocationOmitsZeroLastSeen pins the fix for
// F10: a freshly-discovered signal without a LastSeen timestamp
// must NOT surface "0001-01-01T00:00:00Z" as the location's
// last_seen. The entry-level rollup already guarded zero-time;
// the per-location loop did not, leaving operators staring at
// year-0001 timestamps for every brand-new install.
func TestRollupComponents_LocationOmitsZeroLastSeen(t *testing.T) {
	signals := []inventory.AISignal{
		{
			Component: &inventory.AIComponent{Ecosystem: "pypi", Name: "openai"},
			Detector:  "package_manifest",
			Evidence: []inventory.AIEvidence{
				{Basename: "pyproject.toml", Quality: 1.0, MatchKind: "exact"},
			},
			// LastSeen intentionally zero to repro the original
			// "0001-01-01T00:00:00Z" surfacing bug.
		},
	}
	out := rollupComponents(signals, inventory.ConfidenceParams{}, false)
	if len(out) != 1 || len(out[0].Locations) != 1 {
		t.Fatalf("unexpected rollup shape: %+v", out)
	}
	if got := out[0].Locations[0].LastSeen; got != "" {
		t.Errorf("location LastSeen=%q want empty for zero-time signal", got)
	}
	// And the entry-level field also stays empty for the same reason.
	if out[0].LastSeen != "" {
		t.Errorf("entry LastSeen=%q want empty when no signal has a timestamp", out[0].LastSeen)
	}
}

// TestRollupComponents_LocationKeepsRealLastSeen complements the
// zero-guard above: a real, non-zero timestamp must round-trip
// through the location renderer unchanged so we don't accidentally
// strip valid timestamps.
func TestRollupComponents_LocationKeepsRealLastSeen(t *testing.T) {
	stamp := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	signals := []inventory.AISignal{
		{
			Component: &inventory.AIComponent{Ecosystem: "pypi", Name: "openai"},
			Detector:  "package_manifest",
			Evidence:  []inventory.AIEvidence{{Basename: "pyproject.toml"}},
			LastSeen:  stamp,
		},
	}
	out := rollupComponents(signals, inventory.ConfidenceParams{}, false)
	if got := out[0].Locations[0].LastSeen; got != "2026-05-05T12:00:00Z" {
		t.Errorf("location LastSeen=%q want 2026-05-05T12:00:00Z", got)
	}
}

func TestRollupComponents_SkipsGoneSignals(t *testing.T) {
	now := time.Now().UTC()
	gone := inventory.AISignal{
		Component: &inventory.AIComponent{Ecosystem: "pypi", Name: "openai"},
		Detector:  "package_manifest",
		State:     inventory.AIStateGone,
		Evidence:  []inventory.AIEvidence{{Basename: "pyproject.toml"}},
		LastSeen:  now,
	}
	if out := rollupComponents([]inventory.AISignal{gone}, inventory.ConfidenceParams{}, false); len(out) != 0 {
		t.Fatalf("gone-only component rollup = %+v, want empty", out)
	}
	active := gone
	active.State = inventory.AIStateSeen
	active.Fingerprint = "active"
	active.WorkspaceHash = "ws-active"
	out := rollupComponents([]inventory.AISignal{gone, active}, inventory.ConfidenceParams{}, false)
	if len(out) != 1 {
		t.Fatalf("mixed rollup len=%d want 1: %+v", len(out), out)
	}
	if out[0].InstallCount != 1 || len(out[0].Locations) != 1 {
		t.Fatalf("gone signal contributed to current component rollup: %+v", out[0])
	}
	if out[0].Locations[0].State == inventory.AIStateGone {
		t.Fatalf("gone location leaked into current component rollup: %+v", out[0].Locations)
	}
}

// TestComponentsEndpointGetBypassesCSRF confirms the GET endpoints
// (locations, history, policy show) reach the handler without
// needing the X-DefenseClaw-Client header. The CSRF gate only
// guards mutating methods; if this test ever fails, GET became
// gated and every CLI workflow that uses these endpoints stops
// working.
func TestComponentsEndpointGetBypassesCSRF(t *testing.T) {
	api := aiUsageTestServer(t, false)
	handler := api.tokenAuth(api.apiCSRFProtect(http.HandlerFunc(api.handleAIUsageConfidencePolicy)))

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/ai-usage/confidence/policy?source=default", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (GET should bypass CSRF); body=%s",
			w.Code, w.Body.String())
	}
}
