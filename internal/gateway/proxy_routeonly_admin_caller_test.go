// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// rel-1-0-10:GAP-0764: on a managed host the route-only decision carries the
// proved account with its directory matcher, so routing.admin rules naming
// users or groups apply to their own subjects only. Before, the caller had no
// matcher: every user rule matched every caller and a group rule left every
// caller unconfirmed (identity_unconfirmed, 403 for everyone).
func TestRouteOnlyManagedAdminRulesTellAccountsApart(t *testing.T) {
	f := newRouteOnlyFixture(t)
	f.cfg.DeploymentMode = "managed_enterprise"
	f.cfg.Enterprise.Profile = "standalone"
	f.cfg.Routing.Models = append(f.cfg.Routing.Models, config.RoutingModelBackend{Name: "deep", Provider: "anthropic", Model: "claude-opus-5", BaseURL: f.alt.URL, APIKeyEnv: "ROUTE_ONLY_TEST_KEY_5511"})
	f.cfg.Routing.Signals.Keywords = append(f.cfg.Routing.Signals.Keywords, config.RoutingKeywordSignal{Name: "hard", Keywords: []string{"think hard"}})
	f.cfg.Routing.Decisions = append([]config.RoutingDecisionRule{{Name: "hard", Conditions: []config.RoutingCondition{{Type: "keyword", Name: "hard"}}, ModelRefs: []string{"deep"}}}, f.cfg.Routing.Decisions...)
	f.cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: []config.RoutingAdminRule{
		{ID: "eng1-fast-and-deep", Match: config.RoutingAdminMatch{Users: []string{"1001"}}, Allow: []string{"haiku", "deep"}},
		{ID: "eng2-fast-only", Match: config.RoutingAdminMatch{Users: []string{"1002"}}, Allow: []string{"haiku"}},
		{ID: "contractors-no-cloud", Match: config.RoutingAdminMatch{Groups: []string{"contractors"}}, Action: "deny", Message: "contractors use the local model"},
	}}

	accounts := map[string]profileSubject{
		"1001": {UserID: "1001", IDKind: useridentity.KindPOSIXUID, UserName: "eng1", Groups: []string{"eng"}},
		"1002": {UserID: "1002", IDKind: useridentity.KindPOSIXUID, UserName: "eng2", Groups: []string{"eng"}},
		"1003": {UserID: "1003", IDKind: useridentity.KindPOSIXUID, UserName: "ctr1", Groups: []string{"contractors"}},
	}
	prevSource, prevFacts, prevExists := profileSubjectSource, identityFactsEnabled.Load(), profileGroupExists
	t.Cleanup(func() {
		profileSubjectSource, profileGroupExists = prevSource, prevExists
		identityFactsEnabled.Store(prevFacts)
	})
	identityFactsEnabled.Store(true)
	profileSubjectSource = func(ctx context.Context) (profileSubject, bool) {
		s, ok := verifiedSubjectFromContext(ctx)
		if !ok {
			return profileSubject{}, false
		}
		subject, known := accounts[s.UserID]
		return subject, known
	}
	profileGroupExists = func(context.Context, string) (bool, error) { return true, nil }

	decideAs := func(t *testing.T, uid, prompt string) SemanticRouteOutcome {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/r/claudecode/v1/messages", nil)
		r = r.WithContext(routeOnlyManagedContext(r.Context(), uid, "claudecode"))
		caller, profiles := routeOnlyCaller(r.Context(), uid)
		if !caller.Verified || caller.Key != uid || caller.Matches == nil {
			t.Fatalf("%s: the route-only caller has no verified matcher: %+v", uid, caller)
		}
		body := []byte(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"` + prompt + `"}]}`)
		_, out, _ := f.srv.decide(r, f.cfg, "claudecode", "/v1/messages", config.RoutingAPIMessages, f.cfg.Routing.RouteOnly.Upstreams["claudecode"], engine.CredentialAPIKey, nil, body, caller, profiles)
		return out
	}

	for uid, want := range map[string]string{"1001": "eng1-fast-and-deep", "1002": "eng2-fast-only"} {
		out := decideAs(t, uid, "a quick question")
		if out.Route == nil || out.Result == SemanticRouteDenied {
			t.Fatalf("%s: the model both rules allow: %+v", uid, out)
		}
		if !slices.Equal(out.Route.RuleIDs, []string{want}) {
			t.Fatalf("%s: rule ids %v, want only %s", uid, out.Route.RuleIDs, want)
		}
		for _, warning := range out.Route.Warnings {
			if strings.Contains(warning, "identity_unconfirmed") {
				t.Fatalf("%s: a member of no denied group is unconfirmed: %v", uid, out.Route.Warnings)
			}
		}
		if out.Route.Backend == nil || out.Route.Backend.Alias != "haiku" {
			t.Fatalf("%s: quick question goes to haiku: %+v", uid, out.Route)
		}
	}
	// User 1 is allowed deep; user 2 is denied it, with their own rule named.
	if eng1 := decideAs(t, "1001", "please think hard about this"); eng1.Result == SemanticRouteDenied || eng1.Route.Backend == nil || eng1.Route.Backend.Alias != "deep" {
		t.Fatalf("eng1 is allowed deep: %+v %+v", eng1.Route, eng1.Deny)
	}
	eng2 := decideAs(t, "1002", "please think hard about this")
	if eng2.Result != SemanticRouteDenied || eng2.Deny == nil || !strings.Contains(eng2.Deny.Message, "eng2-fast-only") || strings.Contains(eng2.Deny.Message, "eng1-fast-and-deep") {
		t.Fatalf("eng2 is denied deep by its own rule only: %+v %+v", eng2.Route, eng2.Deny)
	}
	contractor := decideAs(t, "1003", "hello")
	if contractor.Result != SemanticRouteDenied || contractor.Deny == nil || !strings.Contains(contractor.Deny.Message, "contractors use the local model") {
		t.Fatalf("the group deny rule applies to its member: %+v", contractor)
	}
}

// OSS: the gateway owner, unchanged (identity selectors do not apply on a
// per-user gateway).
func TestRouteOnlyCallerWithoutAManagedSubjectIsTheOwner(t *testing.T) {
	caller, profiles := routeOnlyCaller(context.Background(), "501")
	if !caller.Verified || caller.Key != "501" || caller.Source != subjectSourceKernelPeer || caller.Matches != nil || profiles != nil {
		t.Fatalf("OSS caller = %+v %v", caller, profiles)
	}
}
