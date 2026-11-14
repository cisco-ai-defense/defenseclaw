// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// GAP-0576: a sensitive request that must stay local is never sent to the
// cloud model, whatever stops the local route; a keyless local model is
// reached with a login or bearer credential inbound.

func sensitiveRouteOnlyFixture(t *testing.T, local config.RoutingModelBackend) *routeOnlyFixture {
	t.Helper()
	f := newRouteOnlyFixture(t)
	local.Name = "local"
	if local.BaseURL == "-" {
		local.BaseURL = ""
	} else if local.BaseURL == "" {
		local.BaseURL = f.alt.URL
	}
	f.cfg.Routing.Models = append(f.cfg.Routing.Models, local)
	f.cfg.Routing.Signals.Keywords = append(f.cfg.Routing.Signals.Keywords, config.RoutingKeywordSignal{Name: "secret", Keywords: []string{"password"}})
	f.cfg.Routing.Sensitive = &config.RoutingSensitiveConfig{Signals: []string{"secret"}, Aliases: []string{"local"}}
	if err := f.cfg.Routing.Validate(); err != nil {
		t.Fatal(err)
	}
	f.srv = newRouteOnlyServer(newEngineRouter(f.cfg, nil, ""), func() *config.Config { return f.cfg }, f.cfg.DataDir)
	tok, err := f.srv.tokens.Token("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	f.token = tok
	return f
}

// loginInbound is a Claude Code login (OAuth) credential instead of a key.
func loginInbound(r *http.Request) {
	r.Header.Del("X-Api-Key")
	r.Header.Set("Authorization", "Bearer sk-ant-oat01-agent-login")
}

func TestRouteOnlySensitiveKeylessLocalModelGetsTheCall(t *testing.T) {
	f := sensitiveRouteOnlyFixture(t, config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"messages"}})
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("my password is hunter2"), loginInbound)
	if rec.Code != 200 || atomic.LoadInt32(&f.altHits) != 1 || atomic.LoadInt32(&f.origHits) != 0 {
		t.Fatalf("sensitive keyless local: %d local=%d cloud=%d %s", rec.Code, f.altHits, f.origHits, rec.Body.String())
	}
	if f.altHdr.Get("Authorization") != "" || f.altHdr.Get("X-Api-Key") != "" {
		t.Fatalf("the agent login credential crossed to the local model: %v", f.altHdr)
	}
	var got map[string]any
	_ = json.Unmarshal(f.altBody, &got)
	if got["model"] != "qwen2.5" {
		t.Fatalf("local body model = %v", got["model"])
	}
}

func TestRouteOnlySensitiveNeverFallsBackToTheCloud(t *testing.T) {
	for name, tc := range map[string]struct {
		local  config.RoutingModelBackend
		status int
		want   int
		local1 int32
	}{
		"local key missing":      {config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"messages"}, APIKeyEnv: "S1C_UNSET_LOCAL_KEY_9931"}, 200, 403, 0},
		"no base_url and no key": {config.RoutingModelBackend{Provider: "openai", Model: "gpt-4.1-mini", APIs: []string{"messages"}, BaseURL: "-"}, 200, 403, 0},
		"local api mismatch":     {config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5"}, 200, 403, 0},
		"local unavailable":      {config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"messages"}}, http.StatusServiceUnavailable, http.StatusServiceUnavailable, 1},
	} {
		t.Run(name, func(t *testing.T) {
			f := sensitiveRouteOnlyFixture(t, tc.local)
			f.altStatus = tc.status
			rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("my password is hunter2"), loginInbound)
			if atomic.LoadInt32(&f.origHits) != 0 {
				t.Fatalf("a sensitive request reached the cloud model: %d %s", rec.Code, rec.Body.String())
			}
			if rec.Code != tc.want || atomic.LoadInt32(&f.altHits) != tc.local1 {
				t.Fatalf("status = %d (want %d) local=%d: %s", rec.Code, tc.want, f.altHits, rec.Body.String())
			}
			if tc.want == 403 && (!strings.Contains(rec.Body.String(), "sensitive") || !strings.Contains(rec.Body.String(), "local")) {
				t.Fatalf("the refusal does not name the cause: %s", rec.Body.String())
			}
			if tc.want == 403 {
				got := routingAdminRuntime.Decisions().Recent("", true, 1)
				if len(got) != 1 || got[0].Outcome != engine.OutcomeDenied || !slices.Contains(got[0].Reasons, engine.DenyCodeSensitiveLocal) {
					t.Fatalf("the decision record does not say denied: %+v", got)
				}
			}
		})
	}
}

func TestRouteOnlyPlainRequestStillFallsBackWithACause(t *testing.T) {
	f := sensitiveRouteOnlyFixture(t, config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"messages"}})
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello there"), loginInbound)
	if rec.Code != 200 || atomic.LoadInt32(&f.origHits) != 1 {
		t.Fatalf("a plain request must keep its route: %d cloud=%d", rec.Code, f.origHits)
	}
}

func TestAmendRoutingDecisionRecordsWhatWasDone(t *testing.T) {
	ctx := ContextWithRequestID(context.Background(), "req-s1c-amend-1")
	in := &ModelRouterInput{Connector: "codex", Listener: engine.ListenerRouteOnly, RequestModel: "gpt-5"}
	d := &engine.Decision{Outcome: engine.OutcomeApplied, Backend: &engine.Backend{Alias: "local", Model: "qwen2.5"}}
	recordRoutingDecision(ctx, in, d, false)
	amendRoutingDecision(ctx, SemanticRouteOutcome{Result: SemanticRouteDenied, Deny: &engine.DenyReason{Code: engine.DenyCodeSensitiveLocal}, Route: d})
	e, ok := routingAdminRuntime.Decisions().Find("req-s1c-amend-1", "", true)
	if !ok || e.Outcome != engine.OutcomeDenied || e.SelectedAlias != "" || !slices.Contains(e.Reasons, engine.DenyCodeSensitiveLocal) {
		t.Fatalf("amended entry = %+v (found %v)", e, ok)
	}
	var none routingadmin.DecisionEntry
	if routingAdminRuntime.Decisions().Amend("", func(*routingadmin.DecisionEntry) {}) || none.Outcome != "" {
		t.Fatal("an empty request id amends nothing")
	}
}

func TestUnroutedSensitivePassthroughIsRefused(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Routing = config.RoutingConfig{
		Enabled: true, Classifier: config.RoutingClassifierRules,
		Models:    []config.RoutingModelBackend{{Name: "local", Provider: "ollama", Model: "qwen2.5", BaseURL: "http://127.0.0.1:11434"}},
		Signals:   config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{{Name: "secret", Keywords: []string{"password"}}}},
		Sensitive: &config.RoutingSensitiveConfig{Signals: []string{"secret"}, SeverityAtLeast: "HIGH", Aliases: []string{"local"}},
	}
	if err := cfg.Routing.Validate(); err != nil {
		t.Fatal(err)
	}
	p := &GuardrailProxy{modelRouter: newEngineRouter(cfg, nil, "")}
	r := httptest.NewRequest(http.MethodPost, "/model/anthropic.claude/invoke", nil)
	for name, in := range map[string]passthroughRouteInput{
		"signal":   {APIFamily: config.RoutingAPIInvoke, Signed: true, Provider: "bedrock", Text: "the password is x"},
		"severity": {APIFamily: config.RoutingAPIInvoke, Signed: true, Provider: "bedrock", Severity: "CRITICAL"},
	} {
		if o := p.gateUnrouted(r, in); o.Result != SemanticRouteDenied || o.Deny == nil || o.Deny.Code != engine.DenyCodeSensitiveLocal {
			t.Fatalf("%s: a signed sensitive request is not refused: %+v", name, o)
		}
	}
	if o := p.gateUnrouted(r, passthroughRouteInput{APIFamily: config.RoutingAPIInvoke, Signed: true, Provider: "bedrock", Text: "hello"}); o.Result == SemanticRouteDenied {
		t.Fatalf("a plain signed request is refused: %+v", o)
	}
}
