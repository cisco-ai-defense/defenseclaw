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
	switch local.BaseURL {
	case "-":
		local.BaseURL = ""
	case "":
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
	isolatedRoutingAdminRuntime(t)
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

func TestRouteOnlyPlainRequestIsNotNarrowed(t *testing.T) {
	f := sensitiveRouteOnlyFixture(t, config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"messages"}})
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello there"), loginInbound)
	if rec.Code != 200 || atomic.LoadInt32(&f.origHits) != 1 || atomic.LoadInt32(&f.altHits) != 0 {
		t.Fatalf("a plain request must keep its route: %d cloud=%d local=%d", rec.Code, f.origHits, f.altHits)
	}
}

// The TV repro: Codex on the Responses API with a Bedrock bearer key and a
// keyless loopback Ollama alias. The sensitive call reaches Ollama with no
// credential, never the cloud upstream.
func TestRouteOnlyCodexBearerSensitiveGoesToKeylessLocal(t *testing.T) {
	f := sensitiveRouteOnlyFixture(t, config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"responses"}})
	f.cfg.Routing.RouteOnly.Connectors = append(f.cfg.Routing.RouteOnly.Connectors, "codex")
	f.cfg.Routing.RouteOnly.Upstreams["codex"] = config.RoutingUpstreamConfig{BaseURL: f.orig.URL, API: "responses"}
	tok, err := f.srv.tokens.Token("codex")
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"model": "openai.gpt-oss-120b", "stream": true, "input": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": "the db password is hunter2"}}}}}
	rec := f.post(t, "/r/codex/responses", body, func(r *http.Request) {
		r.Header.Del("X-Api-Key")
		r.Header.Set("Authorization", "Bearer ABSKbedrock-short-term-key")
		r.Header.Set(routeTokenHeader, tok)
	})
	if atomic.LoadInt32(&f.origHits) != 0 || atomic.LoadInt32(&f.altHits) != 1 || rec.Code != 200 {
		t.Fatalf("codex sensitive: %d local=%d cloud=%d %s", rec.Code, f.altHits, f.origHits, rec.Body.String())
	}
	if f.altHdr.Get("Authorization") != "" {
		t.Fatal("the Bedrock bearer key crossed to the local model")
	}
}

func TestRouteOnlySensitiveUnroutedAPIIsRefused(t *testing.T) {
	f := sensitiveRouteOnlyFixture(t, config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"messages"}})
	rec := f.post(t, "/r/claudecode/v1/messages/count_tokens", messagesBody("my password is hunter2"), loginInbound)
	if rec.Code != 403 || atomic.LoadInt32(&f.origHits) != 0 || !strings.Contains(rec.Body.String(), "sensitive") {
		t.Fatalf("sensitive count_tokens: %d cloud=%d %s", rec.Code, f.origHits, rec.Body.String())
	}
	rec = f.post(t, "/r/claudecode/v1/messages/count_tokens", messagesBody("hello"), loginInbound)
	if rec.Code != 200 || atomic.LoadInt32(&f.origHits) != 1 {
		t.Fatalf("plain count_tokens must pass: %d cloud=%d", rec.Code, f.origHits)
	}
}

func TestRouteOnlySensitiveNeverSendsAnUncheckedBody(t *testing.T) {
	f := sensitiveRouteOnlyFixture(t, config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"messages"}})
	big := func(r *http.Request) { r.ContentLength = routeOnlyBodyCap + 1 }
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), big); rec.Code != http.StatusRequestEntityTooLarge || atomic.LoadInt32(&f.origHits) != 0 {
		t.Fatalf("over the cap with routing.sensitive: %d cloud=%d", rec.Code, f.origHits)
	}
	f.srv.heldBytes = routeOnlyBufferBudget
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != http.StatusServiceUnavailable || atomic.LoadInt32(&f.origHits) != 0 {
		t.Fatalf("budget full with routing.sensitive: %d cloud=%d", rec.Code, f.origHits)
	}
	f.srv.heldBytes = 0
	// Without routing.sensitive the 1.0.10 bound stays: forwarded unrouted.
	plain := newRouteOnlyFixture(t)
	plain.srv.heldBytes = routeOnlyBufferBudget
	if rec := plain.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != 200 || atomic.LoadInt32(&plain.origHits) != 1 {
		t.Fatalf("budget full without routing.sensitive: %d cloud=%d", rec.Code, plain.origHits)
	}
}

func TestRouteOnlySensitiveConversationStaysLocal(t *testing.T) {
	f := sensitiveRouteOnlyFixture(t, config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"messages"}})
	session := func(r *http.Request) { loginInbound(r); r.Header.Set("X-Claude-Code-Session-Id", "s1c-session-1") }
	f.post(t, "/r/claudecode/v1/messages", messagesBody("my password is hunter2"), session)
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("now refactor foo"), session)
	if rec.Code != 200 || atomic.LoadInt32(&f.altHits) != 2 || atomic.LoadInt32(&f.origHits) != 0 {
		t.Fatalf("the next turn of a sensitive conversation: %d local=%d cloud=%d", rec.Code, f.altHits, f.origHits)
	}
	other := func(r *http.Request) { loginInbound(r); r.Header.Set("X-Claude-Code-Session-Id", "s1c-session-2") }
	if f.post(t, "/r/claudecode/v1/messages", messagesBody("now refactor foo"), other); atomic.LoadInt32(&f.origHits) != 1 {
		t.Fatalf("another conversation is not narrowed: cloud=%d", f.origHits)
	}
}

func TestRouteOnlySensitiveRefusalIsAudited(t *testing.T) {
	f := sensitiveRouteOnlyFixture(t, config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"messages"}, APIKeyEnv: "S1C_UNSET_LOCAL_KEY_9931"})
	store, logger := testStoreAndLogger(t)
	f.srv.router.SetAuditLogger(logger)
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("my password is hunter2"), loginInbound); rec.Code != 403 {
		t.Fatalf("status %d", rec.Code)
	}
	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Target == "routing.sensitive" && strings.Contains(e.Details, engine.DenyCodeSensitiveLocal) {
			if strings.Contains(e.Details, "hunter2") {
				t.Fatal("the audit row holds prompt text")
			}
			return
		}
	}
	t.Fatalf("no routing.sensitive audit row: %+v", events)
}

func TestGuardrailChatSensitiveWithNoLocalModelIsDenied(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Routing = config.RoutingConfig{
		Enabled: true, Classifier: config.RoutingClassifierRules,
		Models:    []config.RoutingModelBackend{{Name: "local", Provider: "ollama", Model: "qwen2.5", BaseURL: "http://127.0.0.1:11434", APIKeyEnv: "S1C_UNSET_LOCAL_KEY_9931"}},
		Signals:   config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{{Name: "secret", Keywords: []string{"password"}}}},
		Sensitive: &config.RoutingSensitiveConfig{Signals: []string{"secret"}, Aliases: []string{"local"}},
	}
	if err := cfg.Routing.Validate(); err != nil {
		t.Fatal(err)
	}
	p := &GuardrailProxy{modelRouter: newEngineRouter(cfg, nil, "")}
	o := p.routeDetailed(context.Background(), &ModelRouterInput{Text: "my password is x", RequestedProvider: "openai", Model: "gpt-5", Connector: "openclaw"})
	p.applyRouteGate(context.Background(), &o, "openai", "gpt-5")
	if o.Result != SemanticRouteDenied || o.Deny == nil || o.Deny.Code != engine.DenyCodeSensitiveLocal {
		t.Fatalf("chat path: %+v", o)
	}
}

func TestAmendRoutingDecisionRecordsWhatWasDone(t *testing.T) {
	isolatedRoutingAdminRuntime(t)
	ctx := ContextWithRequestID(context.Background(), "req-s1c-amend-1")
	in := &ModelRouterInput{Connector: "codex", Listener: engine.ListenerRouteOnly, RequestModel: "gpt-5", Caller: engine.Caller{Verified: true, Key: "1001"}}
	d := &engine.Decision{Outcome: engine.OutcomeApplied, Backend: &engine.Backend{Alias: "local", Model: "qwen2.5"}}
	caller := recordRoutingDecision(ctx, in, d, true)
	// Another caller that reuses the request id amends nothing.
	if routingAdminRuntime.Decisions().Amend("req-s1c-amend-1", caller+"-other", func(e *routingadmin.DecisionEntry) { e.Outcome = "x" }) {
		t.Fatal("another caller amended the entry")
	}
	amendRoutingDecision(ctx, SemanticRouteOutcome{Result: SemanticRouteDenied, Deny: &engine.DenyReason{Code: engine.DenyCodeSensitiveLocal}, Route: d, recordCaller: caller})
	e, ok := routingAdminRuntime.Decisions().Find("req-s1c-amend-1", "", true)
	if !ok || e.Outcome != engine.OutcomeDenied || e.SelectedAlias != "" || !slices.Contains(e.Reasons, engine.DenyCodeSensitiveLocal) {
		t.Fatalf("amended entry = %+v (found %v)", e, ok)
	}
	if routingAdminRuntime.Decisions().Amend("", caller, func(*routingadmin.DecisionEntry) {}) {
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

func TestPassthroughSensitiveConversationStaysNarrowed(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Routing = config.RoutingConfig{
		Enabled: true, Classifier: config.RoutingClassifierRules,
		Models: []config.RoutingModelBackend{
			{Name: "local", Provider: "ollama", Model: "qwen2.5", BaseURL: "http://127.0.0.1:11434", APIs: []string{"messages"}},
			{Name: "haiku", Provider: "anthropic", Model: "claude-haiku-4-5", APIs: []string{"messages"}},
		},
		Signals:   config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{{Name: "secret", Keywords: []string{"password"}}}},
		Decisions: []config.RoutingDecisionRule{{Name: "default", ModelRefs: []string{"haiku"}}},
		Sensitive: &config.RoutingSensitiveConfig{Signals: []string{"secret"}, Aliases: []string{"local"}},
	}
	if err := cfg.Routing.Validate(); err != nil {
		t.Fatal(err)
	}
	p := &GuardrailProxy{modelRouter: newEngineRouter(cfg, nil, "")}
	call := func(text string) (passthroughRoute, bool, SemanticRouteOutcome) {
		r := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		r.Header.Set("X-Claude-Code-Session-Id", "pt-session-1")
		body, _ := json.Marshal(messagesBody(text))
		return p.routePassthrough(r, passthroughRouteInput{APIFamily: config.RoutingAPIMessages, Body: body, Text: text, Model: "claude-sonnet-4-5",
			InboundOrigin: "https://api.anthropic.com", Provider: "anthropic"})
	}
	if route, ok, o := call("my password is hunter2"); !ok || route.Provider != "ollama" {
		t.Fatalf("sensitive turn: ok=%v %+v %+v", ok, route, o)
	}
	if route, ok, o := call("now refactor foo"); !ok || route.Provider != "ollama" || o.Route == nil || o.Route.Sensitive.Source != engine.SensitiveSourceSticky {
		t.Fatalf("next turn of the conversation: ok=%v %+v %+v", ok, route, o.Route)
	}
}

func TestRouteOnlySensitiveUnreachableLocalIsRefusedAndAudited(t *testing.T) {
	// A port nobody can take: a TCP socket bound and never listening refuses
	// every connection and keeps its port for the whole test. A port that was
	// listened on and released can be handed to any other test or process of a
	// shared box, which then answers the call (GAP-2062).
	closed := "http://" + refusingLocalAddress(t)
	f := sensitiveRouteOnlyFixture(t, config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"messages"}, BaseURL: closed})
	store, logger := testStoreAndLogger(t)
	f.srv.router.SetAuditLogger(logger)
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("my password is hunter2"), func(r *http.Request) {
		loginInbound(r)
		r.Header.Set("X-Request-Id", "req-s1c-unreachable-1")
	})
	if rec.Code != http.StatusBadGateway || atomic.LoadInt32(&f.origHits) != 0 || !strings.Contains(rec.Body.String(), "sensitive") {
		t.Fatalf("unreachable local: %d cloud=%d %s", rec.Code, f.origHits, rec.Body.String())
	}
	events, _ := store.ListEvents(20)
	found := false
	for _, e := range events {
		found = found || (e.Target == "routing.sensitive" && strings.Contains(e.Details, engine.DenyCodeSensitiveLocal))
	}
	if !found {
		t.Fatalf("no audit row: %+v", events)
	}
}

// rel-1-0-10:GAP-0757: the local model of a sensitive request refuses it
// (Ollama does not know the Responses input item Codex sends in the lite tool
// mode): the agent gets a DefenseClaw error naming routing.sensitive, the
// alias and the model's reason, in the Responses error shape; the cloud model
// is never tried.
func TestRouteOnlySensitiveLocalRefusalIsNamed(t *testing.T) {
	var localHits int32
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&localHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"input[0]: unknown input item type additional_tools","type":"invalid_request_error"}}`))
	}))
	t.Cleanup(local.Close)
	f := sensitiveRouteOnlyFixture(t, config.RoutingModelBackend{Provider: "ollama", Model: "qwen2.5", APIs: []string{"responses"}, BaseURL: local.URL})
	store, logger := testStoreAndLogger(t)
	f.srv.router.SetAuditLogger(logger)
	f.cfg.Routing.RouteOnly.Connectors = append(f.cfg.Routing.RouteOnly.Connectors, "codex")
	f.cfg.Routing.RouteOnly.Upstreams["codex"] = config.RoutingUpstreamConfig{BaseURL: f.orig.URL, API: "responses"}
	tok, err := f.srv.tokens.Token("codex")
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"model": "openai.gpt-oss-120b", "input": []any{
		map[string]any{"type": "additional_tools", "tools": []any{}},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": "the db password is hunter2"}}},
	}}
	rec := f.post(t, "/r/codex/responses", body, func(r *http.Request) {
		r.Header.Del("X-Api-Key")
		r.Header.Set("Authorization", "Bearer ABSKbedrock-short-term-key")
		r.Header.Set(routeTokenHeader, tok)
	})
	if atomic.LoadInt32(&f.origHits) != 0 || atomic.LoadInt32(&localHits) != 1 {
		t.Fatalf("local=%d cloud=%d", localHits, f.origHits)
	}
	var got struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Error.Type != "invalid_request_error" {
		t.Fatalf("refusal = %d %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"[DefenseClaw]", "routing.sensitive", "local", "additional_tools", "Nothing was sent to the cloud model", "use_responses_lite"} {
		if !strings.Contains(got.Error.Message, want) {
			t.Fatalf("message %q lacks %q", got.Error.Message, want)
		}
	}
	// Audited as a routing.sensitive refusal, with no provider text.
	events, _ := store.ListEvents(20)
	found := false
	for _, e := range events {
		if e.Target == "routing.sensitive" && strings.Contains(e.Details, engine.DenyCodeSensitiveLocal) {
			found = true
			if strings.Contains(e.Details, "additional_tools") {
				t.Fatalf("the audit row carries the provider text: %s", e.Details)
			}
		}
	}
	if !found {
		t.Fatalf("no routing.sensitive audit row: %+v", events)
	}
}

func TestRouteOnlyProviderErrorTextIsBounded(t *testing.T) {
	for raw, want := range map[string]string{
		`{"error":{"message":"bad item"}}`: "bad item",
		`{"error":"model not found"}`:      "model not found",
		`{"message":"nope"}`:               "nope",
		`not json`:                         "",
		`{"error":{"message":"a\u0000b\nc` + strings.Repeat("x", 300) + `"}}`: "abc" + strings.Repeat("x", 157),
	} {
		if got := routeOnlyProviderErrorText([]byte(raw)); got != want {
			t.Fatalf("%.40s = %q, want %q", raw, got, want)
		}
	}
}
