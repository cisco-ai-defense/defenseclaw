// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Accounts of the own-view tests: two engineers (group eng) and a
// contractor, by uid and by Windows SID (the own-status pipe key).
const (
	ownViewSID1 = "S-1-5-21-1111111111-2222222222-3333333333-4101"
	ownViewSID3 = "S-1-5-21-1111111111-2222222222-3333333333-4103"
	// Group SIDs: on Windows the managed gateway matches a configured group
	// name through its looked-up SID (routingGroupSIDsFor).
	ownViewEngSID = "S-1-5-21-1111111111-2222222222-3333333333-2001"
	ownViewCtrSID = "S-1-5-21-1111111111-2222222222-3333333333-2002"
)

func ownViewAccounts() map[string]profileSubject {
	return map[string]profileSubject{
		"4101":      {UserID: "4101", IDKind: useridentity.KindPOSIXUID, UserName: "eng1", Groups: []string{"eng", ownViewEngSID}},
		"4102":      {UserID: "4102", IDKind: useridentity.KindPOSIXUID, UserName: "eng2", Groups: []string{"eng", ownViewEngSID}},
		"4103":      {UserID: "4103", IDKind: useridentity.KindPOSIXUID, UserName: "ctr1", Groups: []string{"contractors", ownViewCtrSID}},
		ownViewSID1: {UserID: ownViewSID1, IDKind: useridentity.KindWindowsSID, UserName: "eng1", Groups: []string{"eng", ownViewEngSID}},
		ownViewSID3: {UserID: ownViewSID3, IDKind: useridentity.KindWindowsSID, UserName: "ctr1", Groups: []string{"contractors", ownViewCtrSID}},
	}
}

// withOwnViewAccounts makes the directory answer for ownViewAccounts.
func withOwnViewAccounts(t *testing.T) {
	t.Helper()
	accounts := ownViewAccounts()
	prevSource, prevFacts, prevExists := profileSubjectSource, identityFactsEnabled.Load(), profileGroupExists
	prevSID, prevLocalSID := profileGroupSIDLookup, profileGroupLocalSIDLookup
	t.Cleanup(func() {
		profileSubjectSource, profileGroupExists = prevSource, prevExists
		profileGroupSIDLookup, profileGroupLocalSIDLookup = prevSID, prevLocalSID
		identityFactsEnabled.Store(prevFacts)
	})
	identityFactsEnabled.Store(true)
	groupSIDs := map[string]string{"eng": ownViewEngSID, "contractors": ownViewCtrSID}
	lookup := func(name string) (string, error) {
		if sid, ok := groupSIDs[strings.ToLower(name)]; ok {
			return sid, nil
		}
		return "", errProfileGroupUnknown
	}
	profileGroupSIDLookup, profileGroupLocalSIDLookup = lookup, lookup
	profileSubjectSource = func(ctx context.Context) (profileSubject, bool) {
		s, ok := verifiedSubjectFromContext(ctx)
		if !ok {
			return profileSubject{}, false
		}
		subject, known := accounts[s.UserID]
		return subject, known
	}
	profileGroupExists = func(context.Context, string) (bool, error) { return true, nil }
}

func ownViewConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	if !cfg.StandaloneEnterprise() {
		t.Skip("fixture is not a standalone managed config on this platform")
	}
	cfg.Routing.Enabled = true
	cfg.Routing.Models = []config.RoutingModelBackend{{Name: "fast", Provider: "anthropic", Model: "claude-haiku-4-5"}, {Name: "local", Provider: "openai", Model: "qwen", BaseURL: "http://127.0.0.1:11434/v1"}}
	cfg.Routing.Admin = &config.RoutingAdminConfig{
		Rules: []config.RoutingAdminRule{
			{ID: "eng1-claude-fast", Match: config.RoutingAdminMatch{Users: []string{"eng1"}, Connectors: []string{"claudecode"}}, Allow: []string{"fast"}},
			{ID: "eng-any", Match: config.RoutingAdminMatch{Groups: []string{"eng"}}, Allow: []string{"fast", "local"}},
			{ID: "eng2-only", Match: config.RoutingAdminMatch{Users: []string{"eng2", "eng1-not-me"}}, Allow: []string{"local"}},
			{ID: "contractors-no-cloud", Match: config.RoutingAdminMatch{Groups: []string{"contractors"}}, Action: "deny", Message: "contractors use the local model"},
			{ID: "codex-everyone", Match: config.RoutingAdminMatch{Connectors: []string{"codex"}}, Allow: []string{"fast", "local"}},
			{ID: "one-agent", Match: config.RoutingAdminMatch{Agents: []string{"agent-of-eng2"}}, Allow: []string{"local"}},
		},
		Budgets: []config.RoutingBudget{
			{ID: "b-all", Scope: "user", Subject: "*", Period: "month", LimitUSD: 10, OnExceed: "warn"},
			{ID: "b-eng1", Scope: "user", Subject: "eng1", Period: "month", LimitUSD: 20, OnExceed: "downgrade:local"},
			{ID: "b-devs", Scope: "group", Subject: "eng", Period: "month", LimitUSD: 100, OnExceed: "warn"},
			{ID: "b-eng2", Scope: "user", Subject: "eng2", Period: "month", LimitUSD: 5, OnExceed: "deny"},
			{ID: "b-ctr", Scope: "group", Subject: "contractors", Period: "month", LimitUSD: 1, OnExceed: "deny"},
		},
	}
	return cfg
}

type ownView struct {
	Admin bool `json:"admin"`
	Rules []struct {
		ID    string         `json:"id"`
		Match map[string]any `json:"match"`
	} `json:"rules"`
	Budgets []routingBudgetView `json:"budgets"`
}

func readOwnView(t *testing.T, a *APIServer, ctx context.Context, path string) (ownView, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	if strings.HasSuffix(path, "/budgets") {
		a.handleRoutingBudgets(rec, req)
	} else {
		a.handleRoutingEffective(rec, req)
	}
	var v ownView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
	}
	return v, rec.Body.String()
}

func ownRuleIDs(v ownView) []string {
	ids := []string{}
	for _, r := range v.Rules {
		ids = append(ids, r.ID)
	}
	return ids
}

func ownBudgetIDs(v ownView) []string {
	ids := []string{}
	for _, b := range v.Budgets {
		ids = append(ids, b.ID)
	}
	return ids
}

// rel-1-0-10:GAP-1129: on a managed host routing rules list and routing
// budgets list said [] (scope own) for a standard user although
// routing.admin rules and budgets named that user and routing status recent
// showed them applying: the gateway sent rules to administrators only and
// a user saw only * user budgets. A user now reads the rules and budgets
// that apply to them (proved with the evaluator matcher, by name and by
// group, over the hook socket uid and the Windows pipe SID), and never a
// selector, a subject, another account's rule or budget, or a group pool's
// spend.
func TestRoutingOwnRulesAndBudgetsListWhatAppliesToTheCaller(t *testing.T) {
	cfg := ownViewConfig(t)
	withOwnViewAccounts(t)
	now := time.Now().UTC()
	isolatedRoutingAdminRuntimeAt(t, now)
	if routingAdminRuntime.For(cfg) == nil {
		t.Fatal("evaluator")
	}
	routingAdminRuntime.Ledger().ApplyRemote([]string{"b-all", "b-eng1", "b-devs", "b-eng2", "b-ctr"}, nil, now)
	routingAdminRuntime.Charge([]string{"user:b-eng1:=" + routingadmin.LocalSubjectHash("eng1")}, 3, now)
	routingAdminRuntime.Charge([]string{"group:b-devs:" + routingadmin.LocalSubjectHash("eng")}, 50, now)
	a := &APIServer{scannerCfg: cfg}

	for _, tc := range []struct {
		name        string
		ctx         context.Context
		rules       []string
		budgets     []string
		mustNotShow []string
	}{
		{"eng1 over the hook socket", hookPeerContext(t, 4101, "eng1"),
			[]string{"eng1-claude-fast", "eng-any", "codex-everyone"}, []string{"b-all", "b-eng1", "b-devs"},
			[]string{"eng2", "contractors", "b-ctr", "one-agent", "agent-of", "\"users\"", "\"groups\"", "\"agents\"", "Users", "Groups", "\"subject\""}},
		{"eng2 over the hook socket", hookPeerContext(t, 4102, "eng2"),
			[]string{"eng-any", "eng2-only", "codex-everyone"}, []string{"b-all", "b-devs", "b-eng2"},
			[]string{"eng1", "contractors", "\"users\"", "Users", "\"subject\""}},
		{"eng1 over the Windows pipe", withRoutingPipeCaller(context.Background(), ownViewSID1),
			[]string{"eng1-claude-fast", "eng-any", "codex-everyone"}, []string{"b-all", "b-eng1", "b-devs"},
			[]string{"eng2", "contractors", "\"users\"", "\"groups\""}},
		{"contractor over the Windows pipe", withRoutingPipeCaller(context.Background(), ownViewSID3),
			[]string{"contractors-no-cloud", "codex-everyone"}, []string{"b-all", "b-ctr"},
			[]string{"eng1", "eng2", "b-devs", "\"groups\""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, raw := readOwnView(t, a, tc.ctx, "/api/v1/routing/effective")
			if v.Admin {
				t.Fatal("a standard user is not an administrator")
			}
			if got := ownRuleIDs(v); !slices.Equal(got, tc.rules) {
				t.Fatalf("own rules %v, want %v (%s)", got, tc.rules, raw)
			}
			if got := ownBudgetIDs(v); !slices.Equal(got, tc.budgets) {
				t.Fatalf("own budgets %v, want %v (%s)", got, tc.budgets, raw)
			}
			for _, hidden := range tc.mustNotShow {
				if strings.Contains(raw, hidden) {
					t.Fatalf("own view shows %s: %s", hidden, raw)
				}
			}
			b, _ := readOwnView(t, a, tc.ctx, "/api/v1/routing/budgets")
			if got := ownBudgetIDs(b); !slices.Equal(got, tc.budgets) {
				t.Fatalf("budgets list %v, want %v", got, tc.budgets)
			}
			for _, budget := range v.Budgets {
				switch budget.ID {
				case "b-eng1":
					if budget.SpentUSD == nil || *budget.SpentUSD != 3 {
						t.Fatalf("own named budget shows own spend: %+v", budget)
					}
				case "b-devs":
					// 50 of 100 USD spent: a member sees only that it is not
					// used up (spend or percent with the limit is the other
					// members' spend too).
					if budget.SpentUSD != nil || budget.PercentUsed != nil || budget.Exceeded {
						t.Fatalf("a group pool shows only whether it is used up: %+v", budget)
					}
				}
			}
		})
	}
}

func hookPeerContext(t *testing.T, uid int, name string) context.Context {
	t.Helper()
	if uid == os.Geteuid() {
		t.Skip("the test process runs as the fixture account (an administrator)")
	}
	return withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, Name: name})
}

// rel-1-0-10:GAP-1154: GET /usage?by=group returned no rows on a managed
// host although routing.admin group rules and group budgets acted on the
// same calls: nothing set the groups of a usage record. A verified caller's
// record now carries the routing.admin groups the caller is proved a member
// of (the names the administrator wrote, bounded), and nothing on OSS.
func TestUsageRecordsCarryTheProvedRoutingAdminGroups(t *testing.T) {
	cfg := ownViewConfig(t)
	withOwnViewAccounts(t)
	ctx := withPinnedGeneration(context.Background(), &Generation{Config: cfg, N: 1})
	groupsOf := func(t *testing.T, ctx context.Context, subject string) []string {
		t.Helper()
		var f modelusage.CallFacts
		usageIdentity(routeOnlyManagedContext(ctx, subject, "claudecode"), &f)
		if !f.IdentityVerified || f.Subject != subject {
			t.Fatalf("%s: not a verified record: %+v", subject, f)
		}
		return f.Groups
	}
	for subject, want := range map[string][]string{"4101": {"eng"}, "4103": {"contractors"}, ownViewSID1: {"eng"}} {
		if got := groupsOf(t, ctx, subject); !slices.Equal(got, want) {
			t.Fatalf("%s: groups %v, want %v", subject, got, want)
		}
	}

	// Bounded: configured names only, at most 16 (usageGroupsMax).
	many := ownViewConfig(t)
	member := ownViewAccounts()["4101"]
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("g%02d", i)
		member.Groups = append(member.Groups, name)
		many.Routing.Admin.Rules = append(many.Routing.Admin.Rules, config.RoutingAdminRule{ID: "r-" + name, Match: config.RoutingAdminMatch{Groups: []string{name}}, Allow: []string{"fast"}})
	}
	member.Groups = append(member.Groups, "not-in-config")
	prev := profileSubjectSource
	t.Cleanup(func() { profileSubjectSource = prev })
	profileSubjectSource = func(context.Context) (profileSubject, bool) { return member, true }
	got := groupsOf(t, withPinnedGeneration(context.Background(), &Generation{Config: many, N: 1}), "4101")
	profileSubjectSource = prev
	if len(got) != 16 || got[0] != "eng" || slices.Contains(got, "not-in-config") {
		t.Fatalf("bounded groups: %v", got)
	}

	// OSS: identity selectors do not apply; no groups.
	oss := &config.Config{}
	oss.Routing.Admin = cfg.Routing.Admin
	if got := groupsOf(t, withPinnedGeneration(context.Background(), &Generation{Config: oss, N: 1}), "4101"); len(got) != 0 {
		t.Fatalf("OSS records carry no groups: %v", got)
	}
}
