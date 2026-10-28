// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Record, never infer (GAP-0522). alice's group membership is unknown and
// a group assignment gives strict, whose rule pack alone catches the
// marker; the default is permissive. No surface may decide the request on
// a profile the unproven facts may not give her: the hook, the four inspect
// endpoints (through the middleware and as a sandbox relay calls them),
// ACP and the proxy block with the missing fact named, and explain reports
// the refusal. With the groups proven, strict applies
// and nothing is refused.
func TestUnprovenIdentityFactIsRefusedOnEverySurface(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(priorManaged) })
	previous := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(previous) })
	stubProfileSources(t)
	const marker = "unproven_strict_marker_token"
	root := t.TempDir()
	strictDir, permissiveDir := filepath.Join(root, "strict"), filepath.Join(root, "permissive")
	writeRulePackFixtureFile(t, strictDir, "rules/marker.yaml", `version: 1
category: secret
rules:
  - id: UNPROVEN-STRICT-MARKER
    pattern: "`+marker+`"
    title: strict pack fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	writeRulePackFixtureFile(t, permissiveDir, "rules/other.yaml", `version: 1
category: secret
rules:
  - id: UNPROVEN-PERMISSIVE-OTHER
    pattern: "unproven_unrelated_token"
    title: permissive pack fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict":     {Mode: "action", BlockAt: "high", RulePackDir: strictDir},
		"permissive": {Mode: "action", BlockAt: "high", RulePackDir: permissiveDir},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"eng-strict"}}}}
	cfg.Guardrail.DefaultProfile = "permissive"
	cfg.ACP = config.ACPConfig{
		Enabled: true, Mode: "action", DefaultProfile: "default",
		Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "default"}},
		Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "default"}},
		Profiles: map[string]config.ACPProfile{"default": {
			Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
		}},
	}
	p := identityTestPlatforms[0]
	unknown := identityTestSubject(p, p.providers[1], stateGroupsUnknown, false)
	proven := identityTestSubject(p, p.providers[1], stateProven, true)
	const fact = "group membership is unconfirmed"
	refused := func(reason string) bool { return strings.Contains(reason, "DefenseClaw refused this request: "+fact) }

	hook := func(api *APIServer, subject profileSubject, command string) (action, reason string) {
		t.Helper()
		body := `{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":{"command":"` + command + `"}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/opencode/hook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), testVerifiedSubjectKey{}, subject))
		rec := httptest.NewRecorder()
		api.handleAgentHook("opencode").ServeHTTP(rec, req)
		var resp struct {
			Action string `json:"action"`
			Reason string `json:"reason"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
			t.Fatalf("hook status=%d body=%s", rec.Code, rec.Body.String())
		}
		return resp.Action, resp.Reason
	}
	inspect := func(api *APIServer, subject profileSubject, path string, handler http.HandlerFunc, body string, middleware bool) ToolInspectVerdict {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		ctx := context.WithValue(req.Context(), testVerifiedSubjectKey{}, subject)
		req = req.WithContext(withAuthenticatedInspectConnector(ctx, "codex"))
		rec := httptest.NewRecorder()
		var h http.Handler = handler
		if middleware {
			h = api.guardrailProfileInspectMiddleware(handler)
		}
		h.ServeHTTP(rec, req)
		var verdict ToolInspectVerdict
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &verdict) != nil {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		return verdict
	}

	t.Run("groups unknown", func(t *testing.T) {
		api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
		if action, reason := hook(api, unknown, "ls"); action != "block" || !refused(reason) {
			t.Errorf("hook: action %q, reason %q; want the refusal", action, reason)
		}
		for _, check := range []struct {
			path    string
			handler http.HandlerFunc
			body    string
		}{
			{"/api/v1/inspect/tool", api.handleInspectTool, `{"tool":"bash","args":{"command":"ls"}}`},
			{"/api/v1/inspect/request", api.handleInspectRequest, `{"content":"hello"}`},
			{"/api/v1/inspect/response", api.handleInspectResponse, `{"content":"hello"}`},
			{"/api/v1/inspect/tool-response", api.handleInspectToolResponse, `{"tool":"bash","output":"hello"}`},
		} {
			for _, middleware := range []bool{true, false} {
				if verdict := inspect(api, unknown, check.path, check.handler, check.body, middleware); verdict.Action != "block" || !refused(verdict.Reason) {
					t.Errorf("%s (middleware %v): verdict %+v; want the refusal", check.path, middleware, verdict)
				}
			}
		}

		frame := `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s","prompt":[{"type":"text","text":"hello"}]}}`
		body, err := json.Marshal(acp.Evaluation{
			Profile: "default", Mode: acp.ModeAction, AgentID: "kiro", ClientID: "zed",
			Direction: acp.ClientToAgent, Surface: acp.SurfacePrompt, Method: "session/prompt", Payload: json.RawMessage(frame),
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body))
		api.handleACPEvaluate(rec, req.WithContext(context.WithValue(req.Context(), testVerifiedSubjectKey{}, unknown)))
		var verdict acp.Verdict
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &verdict) != nil || verdict.Action != "block" || !refused(verdict.Reason) {
			t.Errorf("ACP: status %d body %s; want the refusal", rec.Code, rec.Body.String())
		}

		proxy := &GuardrailProxy{cfg: &config.GuardrailConfig{Connector: "codex"}, gatewayToken: "owner-token"}
		req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
		req.Header.Set("X-DC-Auth", "Bearer owner-token")
		rec = httptest.NewRecorder()
		proxy.handleChatCompletion(rec, req.WithContext(context.WithValue(req.Context(), testVerifiedSubjectKey{}, unknown)))
		if rec.Code != http.StatusForbidden || !refused(rec.Body.String()) {
			t.Errorf("proxy: status %d body %s; want 403 with the refusal", rec.Code, rec.Body.String())
		}

		raw, err := EncodeProfileExplainCallerFacts(ProfileExplainCallerFacts{UID: 70001, Name: "alice", Facts: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Source: useridentity.SourceSSSD, Domain: "corp.example",
			AccountSID: "S-1-5-21-1-2-3-1601", Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(), GroupsPartial: true,
		}})
		if err != nil {
			t.Fatal(err)
		}
		query := url.Values{"user": {"70001"}, "connector": {"codex"}, "caller_facts": {raw}}
		req = httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?"+query.Encode(), nil)
		req.RemoteAddr = "127.0.0.1:40000"
		rec = httptest.NewRecorder()
		api.handleGuardrailProfileResolve(rec, req)
		var explained map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &explained) != nil || explained["refused"] != true {
			t.Fatalf("explain: status %d body %s; want refused", rec.Code, rec.Body.String())
		}
		if reason, _ := explained["refused_reason"].(string); !refused(reason) || !strings.Contains(reason, "profile-explain --user 70001") &&
			!strings.Contains(reason, "profile explain --user 70001") {
			t.Errorf("explain refused_reason %q; want the group fact and the explain command named", reason)
		}

	})

	t.Run("groups proven", func(t *testing.T) {
		api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
		if action, reason := hook(api, proven, "ls"); action == "block" || refused(reason) {
			t.Errorf("hook: action %q, reason %q; want it decided under strict, not refused", action, reason)
		}
		if verdict := inspect(api, proven, "/api/v1/inspect/request", api.handleInspectRequest, `{"content":"`+marker+`"}`, true); verdict.Action != "block" || refused(verdict.Reason) {
			t.Errorf("inspect: verdict %+v; want the strict pack's block", verdict)
		}
	})
}
