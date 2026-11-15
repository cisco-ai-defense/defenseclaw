// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The Cowork row keeps its state to a single word and carries the reason in
// separate fields, in every state the gateway decides on, so a script that
// reads the state is not handed a sentence. The state words are the
// connector ones plus refused.
func TestOwnStatusCoworkRowStateIsOneWordWithSeparateReason(t *testing.T) {
	proven := &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {}, "opencode": {}}}
	unproven := &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": {shared: true}}}
	for _, tc := range []struct {
		name      string
		view      *managedPolicyView
		configure func(*config.Config)
		state     string
		code      string
	}{
		{"claude code protected", proven, nil, "protected", "cowork_hooks"},
		{"claude code policy unproven", unproven, nil, "not confirmed", "claude_code_unverified"},
		{"claude code not configured", proven, func(cfg *config.Config) {
			delete(cfg.Guardrail.Connectors, "claudecode")
		}, "not protected", "claude_code_off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := ownReasonsAPI(t, ownReasonsScenario{view: tc.view, configure: tc.configure})
			raw, err := json.Marshal(api.ownStatusAnswer(context.Background(), "uid", "5001", "alice", ""))
			if err != nil {
				t.Fatal(err)
			}
			var out struct {
				Cowork struct {
					Protected  bool   `json:"protected"`
					State      string `json:"state"`
					ReasonCode string `json:"reason_code"`
					Reason     string `json:"reason"`
				} `json:"cowork"`
			}
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			if out.Cowork.State != tc.state || out.Cowork.ReasonCode != tc.code || out.Cowork.Reason == "" ||
				out.Cowork.Protected != (tc.state == "protected") {
				t.Fatalf("cowork row = %+v, want state %q, code %q and a reason: %s", out.Cowork, tc.state, tc.code, raw)
			}
		})
	}
}

// GAP-0574: the own-status answer names routing on or off, the route-only
// connectors and the caller own budget nearest its limit; users_see none
// keeps the organization-wide facts and drops the budget.
func TestOwnStatusRoutingSummary(t *testing.T) {
	isolatedRoutingAdminRuntime(t)
	cfg := routingAPIConfig()
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"claudecode"}}
	if routingAdminRuntime.For(cfg) == nil {
		t.Fatal("evaluator")
	}
	now := time.Now()
	routingAdminRuntime.Ledger().ApplyRemote([]string{"daily", "eng"}, nil, now)
	routingAdminRuntime.Charge([]string{"user:daily:*:1001"}, 4, now)
	summary := ownRoutingSummary(cfg, "1001", now)
	budget, _ := summary["budget"].(map[string]any)
	if summary["enabled"] != true || budget == nil || budget["id"] != "daily" || budget["percent_used"].(float64) != 40 {
		t.Fatalf("summary = %v", summary)
	}
	if got, _ := summary["route_only"].([]string); len(got) != 1 || got[0] != "claudecode" {
		t.Fatalf("route_only = %v", summary["route_only"])
	}
	if other := ownRoutingSummary(cfg, "1002", now); other["budget"] == nil || other["budget"].(map[string]any)["percent_used"].(float64) != 0 {
		t.Fatalf("another account shares the first account spend: %v", other)
	}
	cfg.Routing.Admin.Visibility = &config.RoutingVisibility{UsersSee: config.RoutingUsersSeeNone}
	hidden := ownRoutingSummary(cfg, "1001", now)
	if hidden["enabled"] != true || hidden["budget"] != nil {
		t.Fatalf("users_see none = %v", hidden)
	}
	if ownRoutingSummary(nil, "1", now) != nil {
		t.Fatal("no configuration still answers")
	}
	if off := ownRoutingSummary(&config.Config{}, "1", now); off["enabled"] != false {
		t.Fatalf("routing off = %v", off)
	}
}
