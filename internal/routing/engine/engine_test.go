// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func testConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Routing = config.RoutingConfig{
		Enabled:    true,
		Classifier: "rules",
		Models: []config.RoutingModelBackend{
			{Name: "fast", Provider: "openai", Model: "gpt-4.1-mini"},
			{Name: "claude", Provider: "anthropic", Model: "claude-haiku-4-5"},
			{Name: "local", Provider: "ollama", Model: "llama3.1", BaseURL: "http://127.0.0.1:11434"},
		},
		Signals: config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{
			{Name: "code", Keywords: []string{"refactor", "stack trace"}},
			{Name: "both", Keywords: []string{"alpha", "beta"}, Operator: "AND"},
			{Name: "secret", Keywords: []string{"akia"}},
		}},
		Decisions: []config.RoutingDecisionRule{
			{Name: "code", Priority: 10, Conditions: []config.RoutingCondition{{Type: "keyword", Name: "code"}}, ModelRefs: []string{"claude", "fast"}},
			{Name: "both", Priority: 20, Conditions: []config.RoutingCondition{{Type: "keyword", Name: "both"}}, ModelRefs: []string{"fast"}},
			{Name: "codex-tools", Priority: 5, Conditions: []config.RoutingCondition{{Type: "connector", Name: "codex"}, {Type: "request", Name: "has_tools"}}, ModelRefs: []string{"fast"}},
			{Name: "default", ModelRefs: []string{"local"}},
		},
	}
	return cfg
}

func mustEngine(t *testing.T, cfg *config.Config, opts Options) *Engine {
	t.Helper()
	if err := cfg.Routing.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	e, err := New(cfg, opts)
	if err != nil || e == nil {
		t.Fatalf("New = %v, %v", e, err)
	}
	return e
}

func chat(text string) Request {
	return Request{Text: text, APIFamily: "chat", Connector: "openclaw", Listener: ListenerGuardrail, Caller: Caller{Key: "1000"}}
}

func TestNilEngineIsPassthrough(t *testing.T) {
	var e *Engine
	if d := e.Decide(context.Background(), chat("x")); d.Outcome != OutcomePassthrough {
		t.Fatalf("nil engine = %+v", d)
	}
	cfg := testConfig()
	cfg.Routing.Enabled = false
	if e, err := New(cfg, Options{}); e != nil || err != nil {
		t.Fatalf("disabled routing builds %v, %v", e, err)
	}
}

func TestRulesClassifierSemantics(t *testing.T) {
	e := mustEngine(t, testConfig(), Options{})
	for _, tc := range []struct {
		name string
		req  Request
		want string
		rule string
	}{
		{"substring, case-insensitive", chat("please REFACTORING this"), "claude", "code"},
		{"phrase", chat("here is a stack trace:"), "claude", "code"},
		{"AND needs all", chat("alpha only"), "local", ""},
		{"AND all present wins on priority", chat("alpha beta refactor"), "fast", "both"},
		{"connector and request", Request{APIFamily: "responses", Connector: "codex", HasTools: true, Caller: Caller{Key: "1"}}, "fast", "codex-tools"},
		{"no match uses the unconditional decision", chat("hello"), "local", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Decide(context.Background(), tc.req)
			if d.Outcome != OutcomeApplied || d.Backend.Alias != tc.want || d.RuleID != tc.rule {
				t.Fatalf("decision = %+v backend %+v, want %s by %q", d, d.Backend, tc.want, tc.rule)
			}
		})
	}
}

func TestDecideSameAPIOnly(t *testing.T) {
	e := mustEngine(t, testConfig(), Options{})
	req := chat("refactor this")
	req.APIFamily = "messages"
	d := e.Decide(context.Background(), req)
	if d.Outcome != OutcomeApplied || d.Backend.Alias != "claude" {
		t.Fatalf("messages = %+v", d)
	}
	req.Text = "hello" // default local serves chat only, so the request goes out unchanged
	if d := e.Decide(context.Background(), req); d.Outcome != OutcomeFallback || d.FailureCode != FailureFiltered {
		t.Fatalf("messages without a compatible alias = %+v", d)
	}
}

func TestDecideProfileOverlayOnlyForVerifiedCallers(t *testing.T) {
	cfg := testConfig()
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"ctr": {Routing: &config.RoutingPolicyConfig{AllowedAliases: []string{"local"}}}}
	e := mustEngine(t, cfg, Options{})
	req := chat("refactor")
	req.Profiles = []string{"ctr"}
	if d := e.Decide(context.Background(), req); d.Backend == nil || d.Backend.Alias != "claude" {
		t.Fatalf("unverified caller got the profile overlay: %+v", d)
	}
	req.Caller.Verified = true
	if d := e.Decide(context.Background(), req); d.Backend == nil || d.Backend.Alias != "local" {
		t.Fatalf("verified ctr caller = %+v, want local", d)
	}
}

type failingClassifier struct{ code string }

func (f failingClassifier) Name() string { return "systemone" }
func (f failingClassifier) Classify(context.Context, ClassifyInput) (ClassifyResult, error) {
	return ClassifyResult{}, &ClassifierError{Code: f.code, Err: errors.New("down")}
}

type lowConfidence struct{}

func (lowConfidence) Name() string { return "systemone" }
func (lowConfidence) Classify(context.Context, ClassifyInput) (ClassifyResult, error) {
	return ClassifyResult{Category: "chat", Confidence: 0.2}, nil
}

func TestDecideClassifierErrorPolicy(t *testing.T) {
	cfg := testConfig()
	cfg.Routing.Classifier = "systemone"
	cfg.Routing.Decisions = cfg.Routing.Decisions[:3] // no unconditional default
	e := mustEngine(t, cfg, Options{Classifier: failingClassifier{code: FailureTimeout}})
	if d := e.Decide(context.Background(), chat("refactor")); d.Outcome != OutcomeFallback || d.FailureCode != FailureTimeout {
		t.Fatalf("on_classifier_error original = %+v", d)
	}
	cfg.Routing.OnClassifierError = "rules"
	e = mustEngine(t, cfg, Options{Classifier: failingClassifier{code: FailureBreakerOpen}})
	if d := e.Decide(context.Background(), chat("refactor")); d.Outcome != OutcomeApplied || d.Backend.Alias != "claude" {
		t.Fatalf("on_classifier_error rules = %+v", d)
	}
	cfg.Routing.OnClassifierError = ""
	cfg.Routing.MinConfidence = 0.6
	cfg.Routing.Categories = map[string]string{"chat": "fast"}
	e = mustEngine(t, cfg, Options{Classifier: lowConfidence{}})
	if d := e.Decide(context.Background(), chat("hi")); d.Outcome != OutcomeFallback || d.FailureCode != FailureLowConfidence {
		t.Fatalf("low confidence = %+v", d)
	}
	cfg.Routing.MinConfidence = 0.1
	e = mustEngine(t, cfg, Options{Classifier: lowConfidence{}})
	if d := e.Decide(context.Background(), chat("hi")); d.Outcome != OutcomeApplied || d.Backend.Alias != "fast" {
		t.Fatalf("category mapping = %+v", d)
	}
}

func TestDecideSensitiveNarrows(t *testing.T) {
	cfg := testConfig()
	cfg.Routing.Sensitive = &config.RoutingSensitiveConfig{SeverityAtLeast: "HIGH", Signals: []string{"secret"}, Aliases: []string{"local"}}
	e := mustEngine(t, cfg, Options{})
	req := chat("refactor")
	req.Severity = "CRITICAL"
	if d := e.Decide(context.Background(), req); d.Backend == nil || d.Backend.Alias != "local" || d.FilteredBy != "sensitive" {
		t.Fatalf("severity narrowing = %+v", d)
	}
	if d := e.Decide(context.Background(), chat("refactor AKIAEXAMPLE")); d.Backend == nil || d.Backend.Alias != "local" {
		t.Fatalf("signal narrowing = %+v", d)
	}
	req.Severity = "LOW"
	if d := e.Decide(context.Background(), req); d.Backend == nil || d.Backend.Alias != "claude" {
		t.Fatalf("below the floor = %+v", d)
	}
}

func TestDecideDeniedProviderManagedOnly(t *testing.T) {
	cfg := testConfig()
	cfg.Routing.Admin = &config.RoutingAdminConfig{DeniedProviders: []string{"openai"}, AllowedAliases: []string{"fast", "claude"}}
	req := chat("hello")
	req.RequestedProvider = "openai"
	oss := mustEngine(t, cfg, Options{})
	if d := oss.Decide(context.Background(), req); d.Outcome != OutcomeFallback {
		t.Fatalf("OSS never denies: %+v", d)
	}
	managed := mustEngine(t, cfg, Options{Managed: true})
	if d := managed.Decide(context.Background(), req); d.Outcome != OutcomeDenied || d.Deny == nil || d.Deny.Code != "routing_admin_denied" {
		t.Fatalf("managed deny = %+v", d)
	}
	req.Text = "refactor" // claude survives: routed, not denied
	if d := managed.Decide(context.Background(), req); d.Outcome != OutcomeApplied || d.Backend.Alias != "claude" {
		t.Fatalf("managed routed = %+v", d)
	}
}

func TestDecideUserOverrideAndCredential(t *testing.T) {
	cfg := testConfig()
	cfg.Routing.AllowUserOverride = true
	e := mustEngine(t, cfg, Options{CredentialOK: func(b Backend, r Request) bool { return b.Alias != "claude" }})
	req := chat("refactor")
	req.RequestedModel = "fast"
	if d := e.Decide(context.Background(), req); d.Source != SourceUserOverride || d.Backend.Alias != "fast" {
		t.Fatalf("override = %+v", d)
	}
	req.RequestedModel = "gpt-x" // not an alias: classifier; claude has no credential so fast
	if d := e.Decide(context.Background(), req); d.Backend == nil || d.Backend.Alias != "fast" {
		t.Fatalf("credential filter = %+v", d)
	}
}

type fakeAdmin struct{ verdict AdminVerdict }

func (f fakeAdmin) Active() bool        { return true }
func (f fakeAdmin) NeedsCategory() bool { return false }
func (f fakeAdmin) Evaluate(_ context.Context, p Policy, _ Request, _ string, _ bool) AdminVerdict {
	v := f.verdict
	if v.Policy.AllowedAliases == nil {
		v.Policy = p
	}
	return v
}
func (f fakeAdmin) Gate(AdminVerdict, GateTarget, bool) *DenyReason { return nil }

func TestDecideAdminForceAndDeny(t *testing.T) {
	e := mustEngine(t, testConfig(), Options{Admin: fakeAdmin{verdict: AdminVerdict{Force: []string{"local"}, ChargeKeys: []string{"user:b:1000"}}}})
	d := e.Decide(context.Background(), chat("refactor"))
	if d.Source != SourceForce || d.Backend.Alias != "local" || len(d.ChargeKeys) != 1 {
		t.Fatalf("force = %+v", d)
	}
	deny := &DenyReason{Code: "budget_exceeded:b"}
	oss := mustEngine(t, testConfig(), Options{Admin: fakeAdmin{verdict: AdminVerdict{Deny: deny}}})
	if d := oss.Decide(context.Background(), chat("refactor")); d.Outcome == OutcomeDenied {
		t.Fatalf("OSS applied an admin deny: %+v", d)
	}
	managed := mustEngine(t, testConfig(), Options{Managed: true, Admin: fakeAdmin{verdict: AdminVerdict{Deny: deny}}})
	if d := managed.Decide(context.Background(), chat("refactor")); d.Outcome != OutcomeDenied || d.Deny != deny {
		t.Fatalf("managed admin deny = %+v", d)
	}
}

type countingClassifier struct{ calls *int }

func (c countingClassifier) Name() string { return "systemone" }
func (c countingClassifier) Classify(context.Context, ClassifyInput) (ClassifyResult, error) {
	*c.calls++
	return ClassifyResult{Aliases: []string{"fast"}, Confidence: 0.9}, nil
}

func TestDecideStickyPerConversation(t *testing.T) {
	cfg := testConfig()
	cfg.Routing.Classifier = "systemone"
	calls := 0
	e := mustEngine(t, cfg, Options{Classifier: countingClassifier{calls: &calls}})
	req := chat("refactor")
	req.ConversationID = "s1"
	for i := 0; i < 3; i++ {
		d := e.Decide(context.Background(), req)
		if d.Backend == nil || d.Backend.Alias != "fast" {
			t.Fatalf("call %d = %+v", i, d)
		}
		if i > 0 && d.Source != SourceSticky {
			t.Fatalf("call %d source = %s, want sticky", i, d.Source)
		}
	}
	if calls != 1 {
		t.Fatalf("classifier calls = %d, want 1", calls)
	}
	req.Caller.Key = "1001" // another user never shares the entry
	e.Decide(context.Background(), req)
	req.ConversationID = "" // no conversation id: no sticky
	e.Decide(context.Background(), req)
	e.Decide(context.Background(), req)
	if calls != 4 {
		t.Fatalf("classifier calls = %d, want 4", calls)
	}
}
