// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0019: profile-explain of an account's 1.0.3 agent identity decides
// as that account's hooks do. The hooks present the agent's current
// identity and match the 1.0.3 agents entry only through the upgrade's
// binding: unbound, explain is refused with the hook's reason; bound, both
// match by agent.
func TestProfileExplainOfA103AgentIdentityDecidesAsTheHook(t *testing.T) {
	stubProfileSources(t)
	in := legacyBridgeInputs("alice@corp.example")
	legacy, current := agentidentity.LegacyAgentID(in), agentidentity.AgentID(in)
	if legacy == "" || legacy == current {
		t.Fatalf("legacy %q, current %q: want two identities", legacy, current)
	}
	// The 1.0.3 rows were pruned; the account's turns since the upgrade
	// recorded its current identity.
	records := []inventory.AgentIdentityRecord{legacyBridgeRecord(current, in.Account)}
	legacyBridgeLedger(t, &records)
	prevLookup, prevBound := profileExplainSubjectLookup, legacyAgentOwnerBound
	t.Cleanup(func() { profileExplainSubjectLookup, legacyAgentOwnerBound = prevLookup, prevBound })
	subject := profileSubject{UserID: "70001", IDKind: useridentity.KindPOSIXUID, UserName: in.Account}
	profileExplainSubjectLookup = func(string) (profileSubject, error) { return subject, nil }
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action"}, "relaxed": {Mode: "observe"}}
	cfg.Guardrail.DefaultProfile = "strict"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{
		Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}},
	}}
	for _, bound := range []bool{false, true} {
		legacyAgentOwnerBound = func(string, string) bool { return bound }
		api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
		hook := api.guardrailProfileSet().matchAgent(&subject, profileSubjectLookup, "codex", nil, profilePathAny, current, func() (profileAgentClaim, bool) {
			return legacyAgentClaim(legacy, in.UserID, in.MachineHash, in.Account, false), true
		})
		if (hook.Refused == "") != bound {
			t.Fatalf("bound=%v: hook decision %+v", bound, hook)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?user=alice&connector=codex&agent="+url.QueryEscape(legacy), nil)
		req.RemoteAddr = "127.0.0.1:40000"
		rec := httptest.NewRecorder()
		api.handleGuardrailProfileResolve(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("bound=%v: HTTP %d: %s", bound, rec.Code, rec.Body.String())
		}
		var got struct {
			Profile, Match string
			Refused        bool   `json:"refused"`
			RefusedReason  string `json:"refused_reason"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("bound=%v: %v: %s", bound, err, rec.Body.String())
		}
		live, _ := api.guardrailProfileSet().explainLiveDecision(&subject, "codex", current, func() (profileAgentClaim, bool) {
			return legacyAgentClaim(legacy, in.UserID, in.MachineHash, in.Account, false), true
		})
		if live.Name != hook.Name || live.Match != hook.Match || live.Refused != hook.Refused {
			t.Errorf("bound=%v: explain's live view %q/%q refused %q; the hook decides %q/%q refused %q", bound, live.Name, live.Match, live.Refused, hook.Name, hook.Match, hook.Refused)
		}
		if got.Profile != hook.Name || got.Match != hook.Match || got.Refused != (hook.Refused != "") || got.RefusedReason != hook.Refused {
			t.Errorf("bound=%v: explain of the 1.0.3 identity %+v; the hook decides %q/%q refused %q", bound, got, hook.Name, hook.Match, hook.Refused)
		}
	}
}

// An agents entry no record derives for the account as its 1.0.3 identity
// is explained by its identity, as before (GAP-0019 changes nothing there).
func TestProfileExplainOfAnUnderivedAgentEntryKeepsItsMatch(t *testing.T) {
	in := legacyBridgeInputs("alice@corp.example")
	other := legacyBridgeInputs("bob@corp.example")
	other.UserID = "70002"
	records := []inventory.AgentIdentityRecord{legacyBridgeRecord(agentidentity.AgentID(in), in.Account)}
	legacyBridgeLedger(t, &records)
	entry := agentidentity.LegacyAgentID(other)
	set := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{entry, agentidentity.AgentID(in)}}},
	}}
	if got, legacy := set.explainAgent(entry, "70001", "codex"); got != entry || legacy != nil {
		t.Errorf("another uid's 1.0.3 identity explained as %q (claim %v)", got, legacy != nil)
	}
	if got, legacy := set.explainAgent(agentidentity.AgentID(in), "70001", "codex"); got != agentidentity.AgentID(in) || legacy != nil {
		t.Errorf("a current identity explained as %q (claim %v)", got, legacy != nil)
	}
}

// With no ledger record of the account (its rows were pruned and its agent
// has not run since the upgrade), explain derives the account's 1.0.3
// identity as the hook path does and decides as the hook does (GAP-0019).
func TestProfileExplainOfA103AgentIdentityWithoutRecordsDecidesAsTheHook(t *testing.T) {
	in := legacyBridgeInputs("alice@corp.example")
	legacy, current := agentidentity.LegacyAgentID(in), agentidentity.AgentID(in)
	records := []inventory.AgentIdentityRecord{}
	legacyBridgeLedger(t, &records)
	prevInputs, prevBound := explainAgentInputs, legacyAgentOwnerBound
	t.Cleanup(func() { explainAgentInputs, legacyAgentOwnerBound = prevInputs, prevBound })
	explainAgentInputs = func(connectorName, userID string) (agentidentity.Inputs, bool) {
		if connectorName != "codex" || userID != in.UserID {
			return agentidentity.Inputs{}, false
		}
		return in, true
	}
	legacyAgentOwnerBound = func(string, string) bool { return false }
	set := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
	}}
	got, claim := set.explainAgent(legacy, in.UserID, "codex")
	if got != current || claim == nil {
		t.Fatalf("explained %q (claim %v), want the current identity %q with its claim", got, claim != nil, current)
	}
	if c, known := claim(); !known || c.ID != legacy || c.Bound {
		t.Errorf("claim %+v known %v: want the unbound 1.0.3 identity", c, known)
	}
	if got, claim := set.explainAgent(legacy, "70002", "codex"); got != legacy || claim != nil {
		t.Errorf("another account's explain of the identity: %q (claim %v)", got, claim != nil)
	}
	if got, claim := set.explainAgent(legacy, in.UserID, "claudecode"); got != legacy || claim != nil {
		t.Errorf("another connector's explain of the identity: %q (claim %v)", got, claim != nil)
	}
}
