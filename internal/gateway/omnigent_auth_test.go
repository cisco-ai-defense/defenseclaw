// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestOmnigentAttachmentOnlyFindingReachesRequestEvaluator(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "omnigent"
	api := &APIServer{scannerCfg: cfg}
	payload := map[string]interface{}{
		"hook_event_name": "UserPromptSubmit",
		"prompt": "Review the attached document.\n\n" +
			`[OmniGent attachment {"filename":"payload.txt","content_type":"text/plain"}]` +
			"\n" + trustExploitKeyword(),
		"omnigent_attachments": []interface{}{
			map[string]interface{}{
				"filename":     "payload.txt",
				"content_type": "text/plain",
				"text":         trustExploitKeyword(),
				"truncated":    false,
			},
		},
	}
	req := normalizeAgentHookRequestWithProfile(
		"omnigent",
		payload,
		connector.NewOmnigentConnector().HookProfile(connector.SetupOpts{}),
	)
	if req.Content == "Review the attached document." || req.Content == "" {
		t.Fatalf("normalized OmniGent request omitted attachment inspection text: %q", req.Content)
	}
	resp := api.evaluateAgentHook(context.Background(), req)
	if resp.RawAction != "block" || resp.Severity != "CRITICAL" {
		t.Fatalf("attachment-only finding verdict = action %q severity %q, want block/CRITICAL", resp.RawAction, resp.Severity)
	}
}

func TestTokenAuthOmnigentScopedOTLP(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		token  string
		want   int
	}{
		{name: "correct", source: "omnigent", token: "omnigent-scoped-token", want: http.StatusOK},
		{name: "missing", source: "omnigent", want: http.StatusUnauthorized},
		{name: "wrong", source: "omnigent", token: "wrong-token", want: http.StatusUnauthorized},
		{name: "master rejected", source: "omnigent", token: "master-token", want: http.StatusUnauthorized},
		{name: "cross connector rejected", source: "codex", token: "omnigent-scoped-token", want: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Gateway.Token = "master-token"
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
			api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{
				connector.OTLPScopeOmnigent: "omnigent-scoped-token",
				connector.OTLPScopeCodex:    "codex-scoped-token",
			})
			called := false
			handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodPost, "/v1/traces", nil)
			req.RemoteAddr = "127.0.0.1:54321"
			if tc.source != "" {
				req.Header.Set(otelSourceHeader, tc.source)
			}
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.want)
			}
			if got := called; got != (tc.want == http.StatusOK) {
				t.Fatalf("next handler called = %v, want %v", got, tc.want == http.StatusOK)
			}
		})
	}
}

func TestOmnigentHookTokenRevocationInvalidatesGatewayAndRotates(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	oldToken, err := connector.EnsureHookAPIToken(dataDir, "omnigent")
	if err != nil {
		t.Fatalf("EnsureHookAPIToken old: %v", err)
	}
	cfg := &config.Config{DataDir: dataDir}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	if !api.hookAPITokenMatches("omnigent", oldToken) {
		t.Fatal("gateway rejected current OmniGent hook token")
	}
	if err := connector.RemoveHookAPIToken(dataDir, "omnigent"); err != nil {
		t.Fatalf("RemoveHookAPIToken: %v", err)
	}
	if api.hookAPITokenMatches("omnigent", oldToken) {
		t.Fatal("gateway accepted revoked OmniGent hook token")
	}
	newToken, err := connector.EnsureHookAPIToken(dataDir, "omnigent")
	if err != nil {
		t.Fatalf("EnsureHookAPIToken new: %v", err)
	}
	if newToken == oldToken {
		t.Fatal("reinstall reused the revoked OmniGent hook token")
	}
	if api.hookAPITokenMatches("omnigent", oldToken) {
		t.Fatal("gateway accepted old OmniGent token after reinstall")
	}
	if !api.hookAPITokenMatches("omnigent", newToken) {
		t.Fatal("gateway rejected rotated OmniGent token after reinstall")
	}
}
