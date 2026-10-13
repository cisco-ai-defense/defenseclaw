// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sandboxreg

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func decision(kind, scope, host string) sandboxrelay.DecisionRequest {
	return sandboxrelay.DecisionRequest{V: sandboxrelay.WireVersion, Registration: "reg-x", Kind: kind, Host: host, Scope: scope}
}

// The plan's §6.2 truth table, every row and column: "-" is refused (with
// the rule that refuses it), and a user block always passes.
func TestCheckDecisionTruthTable(t *testing.T) {
	yes, no := true, false
	type cell struct {
		kind, scope string
	}
	var (
		session       = cell{sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession}
		always        = cell{sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeAlways}
		unblock       = cell{sandboxrelay.DecisionUnblock, sandboxrelay.DecisionScopeSession}
		unblockAlways = cell{sandboxrelay.DecisionUnblock, sandboxrelay.DecisionScopeAlways}
		block         = cell{sandboxrelay.DecisionEgressBlock, sandboxrelay.DecisionScopeAlways}
		blockS        = cell{sandboxrelay.DecisionEgressBlock, sandboxrelay.DecisionScopeSession}
	)
	rows := []struct {
		name      string
		approvals string
		unblock   *bool
		// refusedBy maps each refused cell to its rule; every other cell
		// passes.
		refusedBy map[cell]string
	}{
		{"unset/unset", "", nil, nil},
		{"unset/true", "", &yes, nil},
		{"unset/false", "", &no, map[cell]string{always: RuleAllowUnblock, unblock: RuleAllowUnblock, unblockAlways: RuleAllowUnblock}},
		{"session/unset", config.OpenShellUserApprovalsSession, nil, map[cell]string{always: RuleUserApprovals, unblockAlways: RuleUserApprovals}},
		{"session/true", config.OpenShellUserApprovalsSession, &yes, map[cell]string{always: RuleUserApprovals, unblockAlways: RuleUserApprovals}},
		{"session/false", config.OpenShellUserApprovalsSession, &no, map[cell]string{
			always: RuleUserApprovals, unblock: RuleAllowUnblock, unblockAlways: RuleAllowUnblock}},
		{"none/unset", config.OpenShellUserApprovalsNone, nil, map[cell]string{
			session: RuleUserApprovals, always: RuleUserApprovals, unblock: RuleUserApprovals, unblockAlways: RuleUserApprovals}},
		{"none/true", config.OpenShellUserApprovalsNone, &yes, map[cell]string{
			session: RuleUserApprovals, always: RuleUserApprovals, unblock: RuleUserApprovals, unblockAlways: RuleUserApprovals}},
		{"none/false", config.OpenShellUserApprovalsNone, &no, map[cell]string{
			session: RuleUserApprovals, always: RuleUserApprovals, unblock: RuleUserApprovals, unblockAlways: RuleUserApprovals}},
	}
	for _, row := range rows {
		f := config.OpenShellAdminConfig{UserApprovals: row.approvals, AllowUnblock: row.unblock}
		for _, c := range []cell{session, always, unblock, unblockAlways, block, blockS} {
			err := CheckDecision(f, decision(c.kind, c.scope, "api.example.org"))
			want, refusedCell := row.refusedBy[c]
			var refusal *DecisionRefusedError
			switch {
			case !refusedCell && err != nil:
				t.Errorf("%s: %s/%s refused: %v", row.name, c.kind, c.scope, err)
			case refusedCell && !errors.As(err, &refusal):
				t.Errorf("%s: %s/%s = %v, want refused by %s", row.name, c.kind, c.scope, err, want)
			case refusedCell && refusal.Rule != want:
				t.Errorf("%s: %s/%s refused by %s, want %s", row.name, c.kind, c.scope, refusal.Rule, want)
			case refusedCell && !strings.HasPrefix(refusal.Message, sandboxapi.AdminMessage):
				t.Errorf("%s: %s/%s message %q does not start with the admin sentence", row.name, c.kind, c.scope, refusal.Message)
			}
		}
	}
}

// A direct call to the decisions route past the floor: the floor's own
// egress lists are never opened by an allow or an unblock in any scope,
// whatever the approvals settings, while a user block of the same host
// still passes; and what is not a decision is refused as such.
func TestCheckDecisionDirectRoutePastFloor(t *testing.T) {
	f := config.OpenShellAdminConfig{
		EgressBlock:     []string{"pastebin.com", "203.0.113.0/24"},
		EgressAllowOnly: []string{"api.anthropic.com", "*.amazonaws.com", "github.com", "203.0.113.7"},
	}
	for _, tc := range []struct {
		host, rule string
	}{
		{"pastebin.com", RuleEgressBlock},
		{"files.pastebin.com", RuleEgressBlock}, // a blocked name blocks its subdomains
		{"PASTEBIN.COM.", RuleEgressBlock},
		{"203.0.113.7", RuleEgressBlock},
		{"api.example.net", RuleEgressAllowOnly},
		{"sub.github.com", RuleEgressAllowOnly}, // allow-only entries match exactly
	} {
		for _, kind := range []string{sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionUnblock} {
			for _, scope := range []string{sandboxrelay.DecisionScopeSession, sandboxrelay.DecisionScopeAlways} {
				var refusal *DecisionRefusedError
				if err := CheckDecision(f, decision(kind, scope, tc.host)); !errors.As(err, &refusal) || refusal.Rule != tc.rule {
					t.Errorf("%s %s/%s = %v, want refused by %s", tc.host, kind, scope, err, tc.rule)
				}
			}
		}
		if err := CheckDecision(f, decision(sandboxrelay.DecisionEgressBlock, sandboxrelay.DecisionScopeAlways, tc.host)); err != nil {
			t.Errorf("user block of %s refused: %v", tc.host, err)
		}
	}
	for _, host := range []string{"api.anthropic.com", "bedrock-runtime.us-east-1.amazonaws.com", "github.com"} {
		if err := CheckDecision(f, decision(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeAlways, host)); err != nil {
			t.Errorf("%s inside the floor refused: %v", host, err)
		}
	}
	for _, d := range []sandboxrelay.DecisionRequest{
		decision("operator", sandboxrelay.DecisionScopeSession, "api.anthropic.com"),
		decision(sandboxrelay.DecisionEgressAllow, "forever", "api.anthropic.com"),
		decision(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession, "*.amazonaws.com"),
		decision(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession, "10.0.0.0/8"),
		decision(sandboxrelay.DecisionEgressBlock, sandboxrelay.DecisionScopeAlways, ""),
		decision(sandboxrelay.DecisionEgressBlock, sandboxrelay.DecisionScopeAlways, strings.Repeat("a", 254)),
	} {
		var refusal *DecisionRefusedError
		if err := CheckDecision(f, d); !errors.As(err, &refusal) || refusal.Rule != RuleInvalid {
			t.Errorf("%+v = %v, want refused as invalid", d, err)
		}
	}
}

// Saved decisions are capped by the floor at every resolve: a profile that
// tightened takes back what it no longer allows, and keeps user blocks.
func TestCapDecisions(t *testing.T) {
	saved := []Decision{
		{ID: "d1", Kind: sandboxrelay.DecisionEgressAllow, Host: "a.example.org", Scope: sandboxrelay.DecisionScopeAlways},
		{ID: "d2", Kind: sandboxrelay.DecisionUnblock, Host: "b.example.org", Scope: sandboxrelay.DecisionScopeAlways},
		{ID: "d3", Kind: sandboxrelay.DecisionEgressBlock, Host: "c.example.org", Scope: sandboxrelay.DecisionScopeAlways},
	}
	if got := CapDecisions(config.OpenShellAdminConfig{}, saved); len(got) != 3 {
		t.Fatalf("an unset floor kept %d of 3", len(got))
	}
	got := CapDecisions(config.OpenShellAdminConfig{UserApprovals: config.OpenShellUserApprovalsSession}, saved)
	if len(got) != 1 || got[0].ID != "d3" {
		t.Fatalf("a session-only floor kept %+v, want only the user block", got)
	}
}

// A decision for this computer is a host-port ask's answer: allow_host_ports
// decides it, for the session only, whatever the egress lists say.
func TestCheckDecisionHostPort(t *testing.T) {
	if openShellHostAlias != packs.OpenShellHostAlias {
		t.Fatalf("host alias %q, want packs' %q", openShellHostAlias, packs.OpenShellHostAlias)
	}
	allowOnly := config.OpenShellAdminConfig{EgressAllowOnly: []string{"api.anthropic.com"}}
	if err := CheckDecision(allowOnly, decision(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession, "HOST.OPENSHELL.INTERNAL")); err != nil {
		t.Fatalf("a host port under egress_allow_only = %v", err)
	}
	no := false
	var refusal *DecisionRefusedError
	if err := CheckDecision(config.OpenShellAdminConfig{AllowHostPorts: &no},
		decision(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession, openShellHostAlias)); !errors.As(err, &refusal) || refusal.Rule != RuleAllowHostPorts {
		t.Fatalf("a host port under allow_host_ports false = %v", err)
	}
	for _, d := range []sandboxrelay.DecisionRequest{
		decision(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeAlways, openShellHostAlias),
		decision(sandboxrelay.DecisionUnblock, sandboxrelay.DecisionScopeSession, openShellHostAlias),
	} {
		if err := CheckDecision(config.OpenShellAdminConfig{}, d); !errors.As(err, &refusal) || refusal.Rule != RuleInvalid {
			t.Errorf("%+v = %v, want refused as invalid", d, err)
		}
	}
	if err := CheckDecision(config.OpenShellAdminConfig{UserApprovals: config.OpenShellUserApprovalsNone},
		decision(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession, openShellHostAlias)); !errors.As(err, &refusal) || refusal.Rule != RuleUserApprovals {
		t.Fatalf("a host port under user_approvals none = %v", err)
	}
}
