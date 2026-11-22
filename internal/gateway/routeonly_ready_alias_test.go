// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// rel-1-0-10 GAP-0921: enterprise status said "route-only: codex ready"
// while the only model its rule allows had no gateway credential, so every
// call was refused.
func TestRouteOnlyReadinessAllowedAliasWithoutCredential(t *testing.T) {
	cfg := readinessConfig(config.RoutingUpstreamConfig{BaseURL: "https://api.openai.com", API: config.RoutingAPIResponses})
	cfg.Routing.RouteOnly.Connectors = []string{"codex"}
	cfg.Routing.RouteOnly.Upstreams = map[string]config.RoutingUpstreamConfig{"codex": {BaseURL: "https://api.openai.com", API: config.RoutingAPIResponses}}
	cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	cfg.Routing.Models = []config.RoutingModelBackend{{Name: "fixture-bedrock", Provider: "bedrock", Model: "fixture-model"}}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: []config.RoutingAdminRule{{ID: "fixture-rule", Match: config.RoutingAdminMatch{Connectors: []string{"codex"}}, Allow: []string{"fixture-bedrock"}}}}
	useRoutingCredentials(t, map[string]string{})
	var signers bedrockSigners

	r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil))
	if r.Ready || !strings.Contains(r.Problem, "every codex caller") || !strings.Contains(r.Fix, "enterprise secret set") || r.Cause != routeCauseAliasNoCredential {
		t.Fatalf("allowed alias without a key: %+v", r)
	}
	// The administrator row names the rule and the model; an ordinary account does not read it.
	if !strings.Contains(r.Problem, "fixture-rule") || !strings.Contains(r.Problem, "fixture-bedrock") {
		t.Fatalf("administrator row does not name them: %+v", r)
	}
	assertNoPolicyNames(t, cfg, r)

	// A named credential that is not stored is the same problem.
	cfg.Routing.Models[0].Credential = "fixture-key"
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); r.Ready || r.Cause != routeCauseAliasNoCredential {
		t.Fatalf("unstored credential: %+v", r)
	}

	// Stored: ready.
	useRoutingCredentials(t, map[string]string{"fixture-key": "fixture-value"})
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); !r.Ready || r.Problem != "" {
		t.Fatalf("stored credential: %+v", r)
	}

	// One usable alias in the rule keeps the connector ready.
	useRoutingCredentials(t, map[string]string{})
	cfg.Routing.Models = append(cfg.Routing.Models, config.RoutingModelBackend{Name: "fixture-openai", Provider: "openai", Model: "fixture-model"})
	cfg.Routing.Admin.Rules[0].Allow = []string{"fixture-bedrock", "fixture-openai"}
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); !r.Ready {
		t.Fatalf("a usable alias remains: %+v", r)
	}

	// A rule for another connector does not matter; OSS never refuses.
	cfg.Routing.Admin.Rules[0].Allow = []string{"fixture-bedrock"}
	cfg.Routing.Admin.Rules[0].Match.Connectors = []string{"claudecode"}
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); !r.Ready {
		t.Fatalf("other connector rule: %+v", r)
	}
	cfg.Routing.Admin.Rules[0].Match.Connectors = []string{"codex"}
	cfg.DeploymentMode, cfg.Enterprise.Profile = "", ""
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); !r.Ready {
		t.Fatalf("OSS host: %+v", r)
	}
}

// assertNoPolicyNames fails when the row, as /health serves it to any local
// account, names a rule id, a model alias or a credential of the policy.
func assertNoPolicyNames(t *testing.T, cfg *config.Config, row routeOnlyReadiness) {
	t.Helper()
	raw, err := json.Marshal(healthRoutingForOrdinaryAccount(routingWithRouteOnly(SubsystemHealth{}, []routeOnlyReadiness{row})))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"fixture-rule", "fixture-bedrock", "fixture-key", "fixture-openai"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("/health names %q: %s", leak, raw)
		}
	}
}

// routrev round 1 P2: a rule scoped to a group, user, agent or category
// refuses only part of the callers, so it is a warning and the connector
// stays ready; only a rule for every caller of the connector blocks it.
func TestRouteOnlyReadinessScopedRuleIsAWarning(t *testing.T) {
	cfg := readinessConfig(config.RoutingUpstreamConfig{BaseURL: "https://api.openai.com", API: config.RoutingAPIResponses})
	cfg.Routing.RouteOnly.Connectors = []string{"codex"}
	cfg.Routing.RouteOnly.Upstreams = map[string]config.RoutingUpstreamConfig{"codex": {BaseURL: "https://api.openai.com", API: config.RoutingAPIResponses}}
	cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	cfg.Routing.Models = []config.RoutingModelBackend{{Name: "fixture-bedrock", Provider: "bedrock", Model: "fixture-model"}}
	useRoutingCredentials(t, map[string]string{})
	var signers bedrockSigners
	for name, match := range map[string]config.RoutingAdminMatch{
		"group":    {Groups: []string{"fixture-group"}, Connectors: []string{"codex"}},
		"user":     {Users: []string{"fixture-user"}},
		"agent":    {Agents: []string{"fixture-agent"}},
		"category": {Categories: []string{"coding"}, Connectors: []string{"codex"}},
	} {
		cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: []config.RoutingAdminRule{{ID: "fixture-rule", Match: match, Allow: []string{"fixture-bedrock"}}}}
		r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil))
		if !r.Ready || r.Warning != routeCauseAliasNoCredential || r.Problem != "" {
			t.Fatalf("%s rule: want ready with a warning, got %+v", name, r)
		}
		if !strings.Contains(r.Detail, "fixture-rule") {
			t.Fatalf("%s rule: the administrator detail does not name the rule: %+v", name, r)
		}
		assertNoPolicyNames(t, cfg, r)
	}
	// severity_at_least never applies on the route-only listener (no guardrail runs there).
	cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: []config.RoutingAdminRule{{ID: "fixture-rule", Match: config.RoutingAdminMatch{SeverityAtLeast: "HIGH", Connectors: []string{"codex"}}, Allow: []string{"fixture-bedrock"}}}}
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); !r.Ready || r.Warning != "" || r.Cause != "" {
		t.Fatalf("severity rule counted on the route-only listener: %+v", r)
	}
	// A connector-wide rule (connectors only, or the connector is listed) blocks.
	cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: []config.RoutingAdminRule{{ID: "fixture-rule", Match: config.RoutingAdminMatch{Connectors: []string{"codex"}}, Allow: []string{"fixture-bedrock"}}}}
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); r.Ready || r.Warning != "" {
		t.Fatalf("connector-wide rule: %+v", r)
	}
}

// routrev2 GAP-0985: a real GET /health by an ordinary account of a managed
// host must carry only the closed cause and generic text of every route-only
// state, on every platform path (custody macOS and Windows, unset upstream,
// alias without a key), and an administrator (the gateway token) still reads
// the full text.
func TestHealthRouteOnlyNamesNothingToAnOrdinaryAccount(t *testing.T) {
	const secretName, ruleID, aliasName, groupName = "rr2-credname-secret", "fixture-rule", "fixture-alias", "fixture-group"
	useRoutingCredentials(t, map[string]string{})
	var signers bedrockSigners
	build := func(upstream config.RoutingUpstreamConfig, models []config.RoutingModelBackend, rules []config.RoutingAdminRule) *config.Config {
		cfg := readinessConfig(upstream)
		cfg.Routing.RouteOnly.Connectors = []string{"codex"}
		cfg.Routing.RouteOnly.Upstreams = map[string]config.RoutingUpstreamConfig{"codex": upstream}
		cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
		cfg.Routing.Models = models
		cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: rules}
		cfg.Gateway.Token = "fixture-gateway-token"
		return cfg
	}
	openai := config.RoutingUpstreamConfig{BaseURL: "https://api.openai.com", API: config.RoutingAPIResponses}
	named := []config.RoutingModelBackend{{Name: aliasName, Provider: "openai", Model: "m", Credential: secretName}}
	bedrockKeyless := []config.RoutingModelBackend{{Name: aliasName, Provider: "bedrock", Model: "m", Credential: secretName}}
	connectorRule := []config.RoutingAdminRule{{ID: ruleID, Match: config.RoutingAdminMatch{Connectors: []string{"codex"}}, Allow: []string{aliasName}}}
	groupRule := []config.RoutingAdminRule{{ID: ruleID, Match: config.RoutingAdminMatch{Groups: []string{groupName}}, Allow: []string{aliasName}}}
	cases := map[string]struct {
		goos          string
		cfg           *config.Config
		cause, warned string
		adminNames    []string // names the administrator row must still carry
	}{
		"custody credential named but not stored": {"darwin", build(openai, named, nil), routeCauseCredentialStored, "", []string{secretName}},
		"custody credential not configured":       {"windows", build(openai, nil, nil), routeCauseNoCredential, "", nil},
		"upstream not set":                        {"linux", build(config.RoutingUpstreamConfig{}, nil, nil), routeCauseUpstreamNotSet, "", nil},
		"allowed alias without a key":             {"linux", build(openai, bedrockKeyless, connectorRule), routeCauseAliasNoCredential, "", []string{ruleID, aliasName}},
		"scoped rule is a warning":                {"linux", build(openai, bedrockKeyless, groupRule), "", routeCauseAliasNoCredential, []string{ruleID, aliasName}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			health := NewSidecarHealth()
			health.SetRouteOnlyReadiness(routeOnlyReadinessFor(tc.cfg, tc.goos, &signers, nil))
			api := NewAPIServer("127.0.0.1:0", health, nil, store, logger, tc.cfg)
			get := func(token string) string {
				req := httptest.NewRequest(http.MethodGet, "/health", nil)
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				rec := httptest.NewRecorder()
				api.handleHealth(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("GET /health = %d: %s", rec.Code, rec.Body)
				}
				return rec.Body.String()
			}
			ordinary := get("")
			for _, leak := range []string{secretName, ruleID, aliasName, groupName, "fixture-gateway-token"} {
				if strings.Contains(ordinary, leak) {
					t.Fatalf("an ordinary account reads %q: %s", leak, ordinary)
				}
			}
			if tc.cause != "" && !strings.Contains(ordinary, `"cause":"`+tc.cause+`"`) {
				t.Fatalf("no closed cause %s: %s", tc.cause, ordinary)
			}
			if tc.warned != "" && !strings.Contains(ordinary, `"warning":"`+tc.warned+`"`) {
				t.Fatalf("no closed warning %s: %s", tc.warned, ordinary)
			}
			adminBody := get("fixture-gateway-token")
			if !strings.Contains(adminBody, "route_only") {
				t.Fatal("the administrator lost the route-only rows")
			}
			for _, want := range tc.adminNames {
				if !strings.Contains(adminBody, want) {
					t.Fatalf("the administrator body lost %q: %s", want, adminBody)
				}
			}
		})
	}
	// routing.last_error of an ordinary account is a closed text, not the start error.
	t.Run("routing last_error", func(t *testing.T) {
		store, logger := testStoreAndLogger(t)
		health := NewSidecarHealth()
		health.SetRouting(StateError, "open /etc/defenseclaw/"+secretName+": fixture start error", nil)
		cfg := build(openai, nil, nil)
		api := NewAPIServer("127.0.0.1:0", health, nil, store, logger, cfg)
		rec := httptest.NewRecorder()
		api.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		if strings.Contains(rec.Body.String(), secretName) || strings.Contains(rec.Body.String(), "fixture start error") {
			t.Fatalf("an ordinary account reads the routing start error: %s", rec.Body)
		}
		// GAP-1008: doctor reads this row, so the closed text points to status.
		if !strings.Contains(rec.Body.String(), "can read the cause in defenseclaw status") || strings.Contains(rec.Body.String(), "defenseclaw doctor") {
			t.Fatalf("the closed routing text must point to defenseclaw status: %s", rec.Body)
		}
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.Header.Set("Authorization", "Bearer fixture-gateway-token")
		rec = httptest.NewRecorder()
		api.handleHealth(rec, req)
		if !strings.Contains(rec.Body.String(), "fixture start error") {
			t.Fatalf("the administrator lost the routing start error: %s", rec.Body)
		}
	})
	// The administrator row keeps the names that doctor shows.
	admin := routeOnlyReadinessFor(cases["custody credential named but not stored"].cfg, "darwin", &signers, nil)
	if len(admin) != 1 || !strings.Contains(admin[0].Problem, secretName) {
		t.Fatalf("the administrator row lost the credential name: %+v", admin)
	}
}

// routrev3 GAP-0989/0986: the administrator row names every allowed model the
// gateway cannot call, including a credential that is named but not stored and
// a Bedrock model whose base_url is loopback (no key can serve it).
func TestRouteOnlyReadinessNamesNamedNotStoredAndBedrockLoopbackModels(t *testing.T) {
	cfg := readinessConfig(config.RoutingUpstreamConfig{BaseURL: "https://api.openai.com", API: config.RoutingAPIResponses})
	cfg.Routing.RouteOnly.Connectors = []string{"codex"}
	cfg.Routing.RouteOnly.Upstreams = map[string]config.RoutingUpstreamConfig{"codex": {BaseURL: "https://api.openai.com", API: config.RoutingAPIResponses}}
	cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	cfg.Routing.Models = []config.RoutingModelBackend{
		{Name: "fixture-named", Provider: "openai", Model: "m", Credential: "fixture-key"},
		{Name: "fixture-loopback", Provider: "bedrock", Model: "m", BaseURL: "http://127.0.0.1:9999"},
	}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: []config.RoutingAdminRule{{ID: "fixture-rule", Match: config.RoutingAdminMatch{Connectors: []string{"codex"}}, Allow: []string{"fixture-named", "fixture-loopback"}}}}
	useRoutingCredentials(t, map[string]string{})
	var signers bedrockSigners
	r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil))
	if r.Ready || !strings.Contains(r.Problem, "fixture-named") || !strings.Contains(r.Problem, "fixture-loopback") {
		t.Fatalf("the administrator row must name both models: %+v", r)
	}
	for _, m := range cfg.Routing.Models {
		if !routeOnlyAliasWithoutKey(cfg, m, "openai") {
			t.Fatalf("%s counts as having a key", m.Name)
		}
	}
}

// rel-1-0-10 GAP-1319: an ordinary account of a managed Windows host is
// pointed at the administrator status command, which names the cause:
// doctor is refused there. Linux and macOS keep doctor, which runs there.
func TestPublicRouteOnlyFixNamesAToolThatWorksOnTheManagedHost(t *testing.T) {
	win := publicRouteOnlyFix("windows")
	if strings.Contains(win, "defenseclaw doctor") || !strings.Contains(win, "enterprise windows status") || !strings.Contains(win, "administrator") {
		t.Fatalf("windows fix = %q", win)
	}
	for _, goos := range []string{"linux", "darwin"} {
		if got := publicRouteOnlyFix(goos); !strings.Contains(got, "defenseclaw doctor as an administrator") {
			t.Fatalf("%s fix = %q", goos, got)
		}
	}
	row := routeOnlyReadiness{Connector: "claudecode", Cause: routeCauseEpoch, Problem: "fixture-problem", Fix: "fixture-fix"}
	public := publicRouteOnly(row)
	if public.Fix != publicRouteOnlyFix(runtime.GOOS) || public.Cause != routeCauseEpoch || strings.Contains(public.Problem+public.Fix, "fixture-") {
		t.Fatalf("public row = %+v", public)
	}
	for _, cause := range []string{routeCauseEpoch, routeCauseAliasNoCredential, routeCauseUpstreamNotSet, routeCauseSigning, routeCauseCredentialStored, routeCauseNoCredential, routeCauseNoEnrolled} {
		if enterprisestatus.RoutingCauseText(cause) == "" {
			t.Fatalf("status has no text for the gateway cause %q", cause)
		}
	}
}
