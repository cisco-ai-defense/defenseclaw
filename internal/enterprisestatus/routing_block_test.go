// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/contracttest"
)

func routingConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Routing.Enabled = true
	cfg.Routing.Classifier = "rules"
	cfg.Routing.Models = []config.RoutingModelBackend{{Name: "fast", Provider: "openai", Model: "m"}, {Name: "deep", Provider: "anthropic", Model: "m"}}
	cfg.Routing.Admin = &config.RoutingAdminConfig{
		Rules:   []config.RoutingAdminRule{{ID: "secret-rule-name"}},
		Budgets: []config.RoutingBudget{{ID: "team-budget-name"}, {ID: "b2"}},
	}
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"codex", "claudecode"}}
	return cfg
}

func TestBuildRoutingCountsAndReadiness(t *testing.T) {
	yes := true
	health := []byte(`{"routing":{"details":{"route_only":[{"connector":"claudecode","ready":true,"problem":"free text with an account name","fix":"x"},{"connector":"codex","ready":false,"problem":"p"}]}}}`)
	state := BuildRouting(RoutingInputs{Config: routingConfig(), Connectors: map[string]ConnectorState{"claudecode": {ManagedHook: &yes}}, Health: health})
	if state == nil || !state.Enabled || state.Classifier != "rules" || state.Models != 2 || state.Rules != 1 || state.Budgets != 2 {
		t.Fatalf("state = %+v", state)
	}
	if len(state.RouteOnly) != 2 || state.RouteOnly[0].Connector != "claudecode" || state.RouteOnly[1].Connector != "codex" {
		t.Fatalf("route_only = %+v", state.RouteOnly)
	}
	cc, cx := state.RouteOnly[0], state.RouteOnly[1]
	if cc.Ready == nil || !*cc.Ready || cc.ManagedHook == nil || !*cc.ManagedHook || cc.ReasonCode != "" {
		t.Fatalf("claudecode = %+v", cc)
	}
	if cx.Ready == nil || *cx.Ready || cx.ReasonCode != RoutingReasonNotReady || cx.ManagedHook != nil {
		t.Fatalf("codex = %+v", cx)
	}
	raw, _ := json.Marshal(state)
	for _, leak := range []string{"secret-rule-name", "team-budget-name", "free text", "account", "openai", "anthropic"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("the block names %q: %s", leak, raw)
		}
	}
}

func TestBuildRoutingWhenTheGatewayDoesNotReport(t *testing.T) {
	for name, health := range map[string][]byte{"no body": nil, "not json": []byte("x"), "no routing member": []byte(`{}`)} {
		state := BuildRouting(RoutingInputs{Config: routingConfig(), Health: health})
		for _, row := range state.RouteOnly {
			if row.Ready != nil || row.ReasonCode != RoutingReasonGatewayDidNotReport {
				t.Fatalf("%s: %+v", name, row)
			}
		}
	}
	state := BuildRouting(RoutingInputs{Config: routingConfig(), Health: []byte(`{"routing":{"details":{"route_only":[{"connector":"codex","ready":true}]}}}`)})
	if state.RouteOnly[0].ReasonCode != RoutingReasonNoReadiness {
		t.Fatalf("a connector the gateway did not list = %+v", state.RouteOnly[0])
	}
}

func TestBuildRoutingIsAbsentWhenNothingIsConfigured(t *testing.T) {
	if BuildRouting(RoutingInputs{}) != nil || BuildRouting(RoutingInputs{Config: &config.Config{}}) != nil {
		t.Fatal("an unconfigured routing reports a block")
	}
	off := &config.Config{}
	off.Routing.Models = []config.RoutingModelBackend{{Name: "fast", Provider: "openai", Model: "m"}}
	if s := BuildRouting(RoutingInputs{Config: off}); s == nil || s.Enabled || s.Models != 1 || s.Classifier != "vllm_sr" {
		t.Fatalf("routing off with models = %+v", s)
	}
}

func TestRoutingLines(t *testing.T) {
	if RoutingLines(nil) != nil {
		t.Fatal("a nil block prints")
	}
	yes := true
	lines := RoutingLines(&RoutingState{Enabled: true, Classifier: "rules", Models: 2, Rules: 1, Budgets: 0,
		RouteOnly: []RoutingRouteOnly{{Connector: "claudecode", Ready: &yes}, {Connector: "codex"}}})
	if len(lines) != 2 || lines[0] != "routing: on classifier=rules models=2 rules=1 budgets=0" || lines[1] != "route-only: claudecode ready, codex unknown" {
		t.Fatalf("lines = %q", lines)
	}
}

// The contract is additive: the block validates against the lifecycle
// schema, a result without it still validates, and the forward projection
// drops it (nothing about routing leaves the device).
func TestRoutingBlockIsAdditiveAndNotForwarded(t *testing.T) {
	schemas := contracttest.Compile(t)
	r := New("status", "standalone", "linux", "1.0.10")
	r.Installed, r.InstalledVersion = true, "1.0.10"
	r.Routing = BuildRouting(RoutingInputs{Config: routingConfig(), Health: []byte(`{"routing":{"details":{"route_only":[{"connector":"codex","ready":true}]}}}`)})
	r.Finish("linux", 0)
	doc := schemas.ValidateValue(t, lifecycleSchema, r)
	if doc["routing"] == nil {
		t.Fatalf("the result carries no routing block: %v", doc)
	}
	projected, _ := schemas.Project(t, "lifecycle-result-forward.schema.json", doc)
	if _, kept := projected["routing"]; kept {
		t.Fatalf("the forward projection keeps routing: %v", projected["routing"])
	}
	old := New("status", "standalone", "linux", "1.0.10")
	old.Installed, old.InstalledVersion = true, "1.0.10"
	old.Finish("linux", 0)
	if doc := schemas.ValidateValue(t, lifecycleSchema, old); doc["routing"] != nil {
		t.Fatalf("a result without routing grew one: %v", doc["routing"])
	}
}

// rel-1-0-10 GAP-1319 (GAP-0965): a not-ready route-only connector names the
// closed cause the gateway reports, in the JSON row and the text lines of
// status and verify, and never the gateway free text; an unknown code, or a
// cause next to a ready row, is dropped. The block still validates.
func TestBuildRoutingNamesTheCauseOfANotReadyConnector(t *testing.T) {
	health := []byte(`{"routing":{"details":{"route_only":[` +
		`{"connector":"claudecode","ready":false,"cause":"route_epoch","problem":"fixture-problem the route epoch file is missing","fix":"fixture-fix"},` +
		`{"connector":"codex","ready":false,"cause":"credential_not_stored","problem":"credential fixture-secret is named in the policy bundle"}]}}}`)
	state := BuildRouting(RoutingInputs{Config: routingConfig(), Health: health})
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		RouteOnly []map[string]any `json:"route_only"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.RouteOnly) != 2 {
		t.Fatalf("route_only = %s (%v)", raw, err)
	}
	if doc.RouteOnly[0]["connector"] != "claudecode" || doc.RouteOnly[0]["cause"] != "route_epoch" || doc.RouteOnly[0]["reason_code"] != "not_ready" ||
		doc.RouteOnly[1]["connector"] != "codex" || doc.RouteOnly[1]["cause"] != "credential_not_stored" {
		t.Fatalf("the rows do not name the cause: %s", raw)
	}
	if strings.Contains(string(raw), "fixture-") {
		t.Fatalf("the block carries gateway free text: %s", raw)
	}
	lines := strings.Join(RoutingLines(state), "\n")
	for _, want := range []string{
		"route-only: claudecode not ready (route_epoch), codex not ready (credential_not_stored)",
		"route-only claudecode: route_epoch: the gateway route epoch is not published",
		"route-only codex: credential_not_stored: a gateway credential the policy names is not stored on this host",
	} {
		if !strings.Contains(lines, want) {
			t.Fatalf("lines do not say %q:\n%s", want, lines)
		}
	}
	if strings.Contains(lines, "fixture-") {
		t.Fatalf("lines carry gateway free text:\n%s", lines)
	}
	schemas := contracttest.Compile(t)
	r := New("status", "standalone", "windows", "1.0.10")
	r.Installed, r.InstalledVersion = true, "1.0.10"
	r.Routing = state
	r.Finish("windows", 0)
	if got := schemas.ValidateValue(t, lifecycleSchema, r); got["routing"] == nil {
		t.Fatalf("the result carries no routing block: %v", got)
	}

	other := []byte(`{"routing":{"details":{"route_only":[` +
		`{"connector":"claudecode","ready":true,"cause":"route_epoch"},` +
		`{"connector":"codex","ready":false,"cause":"free text naming fixture-account"}]}}}`)
	raw, _ = json.Marshal(BuildRouting(RoutingInputs{Config: routingConfig(), Health: other}))
	if strings.Contains(string(raw), `"cause"`) || strings.Contains(string(raw), "fixture-") {
		t.Fatalf("a ready row or an unknown code kept a cause: %s", raw)
	}
}
