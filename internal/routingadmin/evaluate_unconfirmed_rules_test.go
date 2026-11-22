// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// rel-1-0-10:GAP-1155: rule ids are the rules proven to match. A caller whose
// identity facts are unconfirmed is still narrowed and refused on a managed
// device, but routing status no longer lists every user and group rule as
// matched; the gate refusal still names the rules that bind it.
func TestEvaluateListsOnlyProvenRuleIDs(t *testing.T) {
	rules := []config.RoutingAdminRule{
		{ID: "eng1-haiku", Match: config.RoutingAdminMatch{Users: []string{"eng1"}}, Allow: []string{"haiku"}},
		{ID: "eng2-haiku", Match: config.RoutingAdminMatch{Users: []string{"eng2"}}, Allow: []string{"haiku"}},
		{ID: "contractors-no-cloud", Match: config.RoutingAdminMatch{Groups: []string{"contractors"}}, Action: "deny"},
	}
	p := Compile(rules, nil, true)
	v := p.Evaluate(Request{Caller: maybeCaller(), Connector: "claudecode"}, nil, now)
	if denyCode(v) != "identity_unconfirmed:groups" || len(v.RuleIDs) != 0 {
		t.Fatalf("unconfirmed caller: deny %q rule ids %v, want identity_unconfirmed:groups and no rule listed", denyCode(v), v.RuleIDs)
	}
	if v := p.Evaluate(Request{Caller: caller("eng1"), Connector: "claudecode"}, nil, now); len(v.RuleIDs) != 1 || v.RuleIDs[0] != "eng1-haiku" {
		t.Fatalf("eng1 rule ids %v, want eng1-haiku only", v.RuleIDs)
	}

	// Allow rules only: the unconfirmed caller is narrowed to their
	// intersection, and a refusal at the gate names them.
	ev := &evaluator{policy: Compile(rules[:2], nil, true), catalog: map[string]Target{"haiku": {Provider: "anthropic", Model: "claude-haiku-4-5"}}}
	unconfirmed := engine.Caller{Verified: true, Key: "uid:1001", GroupsUnknown: true, Matches: func(config.ProfileMatch) engine.Tri { return engine.Maybe }}
	av := ev.Evaluate(context.Background(), engine.Policy{}, engine.Request{Caller: unconfirmed, Connector: "claudecode"}, "", false)
	if len(av.RuleIDs) != 0 || !av.Bind {
		t.Fatalf("unconfirmed allow rules: rule ids %v bind %t, want none listed and bound", av.RuleIDs, av.Bind)
	}
	d := ev.Gate(av, engine.GateTarget{Provider: "anthropic", Model: "claude-opus-5"}, true)
	if d == nil || d.Code != "routing_admin_denied" || !strings.Contains(d.Message, "eng1-haiku, eng2-haiku") {
		t.Fatalf("gate refusal %+v, want routing_admin_denied naming the binding rules", d)
	}
}
