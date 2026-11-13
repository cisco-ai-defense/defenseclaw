// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func routingAPIConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Routing.Enabled = true
	cfg.Routing.Models = []config.RoutingModelBackend{{Name: "fast", Provider: "openai", Model: "gpt-mini"}}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: []config.RoutingBudget{
		{ID: "daily", Scope: "user", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "warn"},
		{ID: "eng", Scope: "group", Subject: `DCLAB\eng`, Period: "month", LimitUSD: 100, OnExceed: "deny"},
	}}
	return cfg
}

func TestRoutingBudgetViewsShowOwnOnly(t *testing.T) {
	cfg := routingAPIConfig()
	if routingAdminRuntime.For(cfg) == nil {
		t.Fatal("evaluator")
	}
	now := time.Now()
	routingAdminRuntime.Ledger().ApplyRemote([]string{"daily", "eng"}, nil, now)
	routingAdminRuntime.Charge([]string{"user:daily:*:1001"}, 4, now)
	routingAdminRuntime.Charge([]string{"user:daily:*:1002"}, 7, now)
	user := routingBudgetViews(cfg, "1001", false, now)
	if len(user) != 1 || user[0].ID != "daily" || user[0].Subject != "" || *user[0].SpentUSD != 4 || user[0].Exceeded {
		t.Fatalf("user view: %+v", user)
	}
	admin := routingBudgetViews(cfg, "", true, now)
	if len(admin) != 2 || *admin[0].SpentUSD != 11 || !admin[0].Exceeded || admin[1].Subject != `DCLAB\eng` {
		t.Fatalf("admin view: %+v", admin)
	}
}

func TestRoutingExplainHidesOtherUsers(t *testing.T) {
	routingAdminRuntime.Decisions().Record(routingadmin.DecisionEntry{RequestID: "req-explain-1", CallerKey: "owner", Outcome: "applied"})
	a := &APIServer{scannerCfg: &config.Config{}}
	rec := httptest.NewRecorder()
	a.handleRoutingExplain(rec, httptest.NewRequest(http.MethodGet, "/api/v1/routing/explain/req-explain-1", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"outcome":"applied"`) || strings.Contains(rec.Body.String(), "owner") {
		t.Fatalf("own decision: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	a.handleRoutingExplain(rec, httptest.NewRequest(http.MethodGet, "/api/v1/routing/explain/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", rec.Code)
	}
	if got := routingAdminRuntime.Decisions().Recent("1001", false, 5); len(got) != 0 {
		t.Fatalf("another user reads nothing: %+v", got)
	}
}

func TestRoutingTestRefusals(t *testing.T) {
	a := &APIServer{scannerCfg: &config.Config{}}
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"prompt": ""}`, http.StatusBadRequest},
		{`{"prompt": "` + strings.Repeat("x", 9000) + `"}`, http.StatusBadRequest},
		{`not json`, http.StatusBadRequest},
		{`{"prompt": "write code"}`, http.StatusServiceUnavailable},
	} {
		activeEngineRouter.Store(nil)
		routingTestLimiter.Lock()
		routingTestLimiter.last = map[string]time.Time{}
		routingTestLimiter.Unlock()
		rec := httptest.NewRecorder()
		a.handleRoutingTest(rec, httptest.NewRequest(http.MethodPost, "/api/v1/routing/test", strings.NewReader(tc.body)))
		if rec.Code != tc.code {
			t.Fatalf("%.40s: %d %s", tc.body, rec.Code, rec.Body.String())
		}
	}
	if routingTestAllowed("k", true, time.Now()); routingTestAllowed("k", true, time.Now()) {
		t.Fatal("a second dry run within 200 ms is refused")
	}
}

func TestRecordRoutingDecisionKeepsNoPrompt(t *testing.T) {
	in := &ModelRouterInput{Text: "secret prompt text", Connector: "codex", Listener: engine.ListenerGuardrail, RequestModel: "gpt-5"}
	d := &engine.Decision{Outcome: engine.OutcomeApplied, Backend: &engine.Backend{Alias: "fast", Model: "gpt-mini"}, RuleIDs: []string{"r"}}
	recordRoutingDecision(t.Context(), in, d, false)
	got := routingAdminRuntime.Decisions().Recent(routingadmin.OwnerKey, false, 1)
	if len(got) != 1 || got[0].SelectedAlias != "fast" || got[0].RequestedModel != "gpt-5" {
		t.Fatalf("%+v", got)
	}
	b, _ := json.Marshal(got[0])
	if strings.Contains(string(b), "secret prompt") {
		t.Fatal("the prompt must never be recorded")
	}
}

func TestRoutingCallerMatcherUsesTheVerifiedSubject(t *testing.T) {
	if routingCallerMatcher(context.Background()) != nil && !profileProcessOwnerAvailable() {
		t.Fatal("a request without a verified subject has no matcher")
	}
	ctx := withVerifiedSubject(context.Background(), VerifiedSubject{UserID: "1001", IDKind: useridentity.KindPOSIXUID, UserName: "alice", Source: subjectSourcePeerCredentials})
	match := routingCallerMatcher(ctx)
	if match == nil {
		t.Fatal("verified subject: matcher")
	}
	if got := match(config.ProfileMatch{Users: []string{"1001"}}); got != engine.Yes {
		t.Fatalf("own uid: %v", got)
	}
	if got := match(config.ProfileMatch{Users: []string{"1002"}}); got != engine.No {
		t.Fatalf("another uid: %v", got)
	}
}

// profileProcessOwnerAvailable reports whether the test process itself is a
// subject (the per-user gateway owner fallback of profileRequestSubject).
func profileProcessOwnerAvailable() bool {
	_, ok := profileProcessOwnerSubject()
	return ok
}

func TestUnroutedGateCostsNothingWithoutAnAdminPolicy(t *testing.T) {
	p := &GuardrailProxy{}
	in := passthroughRouteInput{Model: "claude", Provider: "anthropic"}
	if o := p.gateUnrouted(httptest.NewRequest(http.MethodGet, "/v1/models", nil), in); o.Result != "" || o.Route != nil {
		t.Fatalf("GET is exempt: %+v", o)
	}
	if o := p.gateUnrouted(httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", nil), in); o.Result != "" || o.Route != nil {
		t.Fatalf("no router: %+v", o)
	}
	denied := SemanticRouteOutcome{Result: SemanticRouteDenied, Deny: &engine.DenyReason{Code: "x"}}
	if got := p.gateOriginal(context.Background(), denied, "anthropic", "claude"); got.Result != SemanticRouteDenied || got.Deny.Code != "x" {
		t.Fatalf("a denied outcome stays denied: %+v", got)
	}
}

func TestRoutingAPIUsersSeeNone(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Routing.Admin = &config.RoutingAdminConfig{Visibility: &config.RoutingVisibility{UsersSee: "none"}}
	a := &APIServer{scannerCfg: cfg}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/routing/effective", nil)
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{UID: 1001, Name: "u"}))
	if !cfg.StandaloneEnterprise() {
		t.Skip("fixture is not a standalone managed config on this platform")
	}
	if _, _, ok := a.routingAPICaller(req, cfg); ok {
		t.Fatal("users_see none: a standard user reads nothing")
	}
	cfg.Routing.Admin.Visibility = nil
	if key, admin, ok := a.routingAPICaller(req, cfg); !ok || admin || key != "1001" {
		t.Fatalf("users_see own: the kernel peer reads its own (key %q admin %v ok %v)", key, admin, ok)
	}
}
