// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// legacyBridgeLedger serves records as the agent ledger and counts reads.
func legacyBridgeLedger(t *testing.T, records *[]inventory.AgentIdentityRecord) *int {
	t.Helper()
	previous := profileAgentLedger
	t.Cleanup(func() { profileAgentLedger = previous })
	asked := 0
	profileAgentLedger = func(filter inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) {
		asked++
		if !filter.Retired {
			t.Errorf("the bridge read the ledger without the records a prune kept aside: %+v", filter)
		}
		return slices.Clone(*records), true
	}
	return &asked
}

func legacyBridgeInputs(account string) agentidentity.Inputs {
	return agentidentity.Inputs{
		MachineHash: agentidentity.MachineHash("0123456789abcdef0123456789abcdef"), UserID: "70001",
		Connector: "codex", InstallFP: "/home/alice/.codex", Account: account,
	}
}

func legacyBridgeRecord(id, account string) inventory.AgentIdentityRecord {
	in := legacyBridgeInputs(account)
	return inventory.AgentIdentityRecord{
		AgentID: id, UserID: in.UserID, UserName: account, Connector: in.Connector,
		InstallFP: in.InstallFP, MachineHash: in.MachineHash,
	}
}

// legacyBridgeDerives stands in for the hook path's derivation of a
// request's 1.0.3 identity, for the agents of accounts.
func legacyBridgeDerives(t *testing.T, accounts ...agentidentity.Inputs) {
	t.Helper()
	previous := profileAgentLegacySource
	t.Cleanup(func() { profileAgentLegacySource = previous })
	profileAgentLegacySource = func(_ context.Context, agent string) (profileAgentClaim, bool) {
		for _, in := range accounts {
			if agentidentity.AgentID(in) == agent {
				// Nothing proves the account incarnation (Bound false).
				return profileAgentClaim{ID: agentidentity.LegacyAgentID(in), UserID: in.UserID, MachineHash: in.MachineHash, Account: in.Account}, true
			}
		}
		return profileAgentClaim{}, false
	}
}

// A 1.0.3 row can have been overwritten by the last namesake under a shared
// UID. Even a sole surviving row cannot prove who owned its legacy ID.
func TestSoleLegacyRowCannotGrantItsRecordedNamesakePolicy(t *testing.T) {
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	lab := agentidentity.AgentID(legacyBridgeInputs("alice@lab.example"))
	records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@lab.example")}
	legacyBridgeLedger(t, &records)
	hook := legacyBridgeHook(t, legacy)
	got, mode := hook(lab)
	if got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
		t.Fatalf("sole overwritten legacy row granted policy: %+v mode %q", got, mode)
	}
}

func TestLegacyOwnerRefusalNamesAnExplainCommandForTheCurrentAgent(t *testing.T) {
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	current := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example"))
	records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@corp.example")}
	legacyBridgeLedger(t, &records)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict": {Mode: "action"}, "relaxed": {Mode: "observe"},
	}
	cfg.Guardrail.DefaultProfile = "strict"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{
		Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}},
	}}
	set := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg).guardrailProfileSet()
	subject := &profileSubject{UserID: "70001", UserName: "alice"}
	hook := set.matchAgent(subject, profileSubjectLookup, "codex", current, func() (profileAgentClaim, bool) {
		return profileAgentClaim{ID: legacy, UserID: "70001", Account: "alice@corp.example"}, true
	})
	if !strings.Contains(hook.Refused, "ownership of a pre-upgrade agent identity is unconfirmed") {
		t.Fatalf("hook decision did not name the missing owner: %+v", hook)
	}
	if !strings.Contains(hook.Refused, " --agent "+current+"`") {
		t.Fatalf("refusal's explain command omits the current agent: %q", hook.Refused)
	}
	explained := set.matchAgent(subject, profileSubjectLookup, "codex", current, nil)
	if explained.Refused == "" || !slices.Contains(explained.Unproven, "agent:unknown") {
		t.Fatalf("the named explain command lost the hook's missing fact: %+v", explained)
	}
}

// A legacy row cannot prove the assignment owner; a current-ID assignment
// remains explicit and can select its account.
func TestLegacyAgentAssignmentNeedsACurrentIDRebind(t *testing.T) {
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	corp, lab := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example")), agentidentity.AgentID(legacyBridgeInputs("alice@lab.example"))
	if legacy == "" || corp == lab || corp == legacy {
		t.Fatalf("legacy %q, corp %q, lab %q: want three identities", legacy, corp, lab)
	}
	records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@corp.example")}
	asked := legacyBridgeLedger(t, &records)
	set := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
	}}
	if got, unresolved, _ := set.profileAgent(corp, nil); got != corp || unresolved == nil || !unresolved(legacy) {
		t.Errorf("corp's agent matched as %q without an unresolved legacy entry", got)
	}
	if got, _, _ := set.profileAgent(lab, nil); got != lab {
		t.Errorf("the lab namesake's agent matches as %q, want its own identity %q", got, lab)
	}
	if *asked != 1 {
		t.Errorf("ledger read %d times, want once for both requests", *asked)
	}
	named := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
		{Profile: "strict", Match: config.ProfileMatch{Agents: []string{corp}}},
	}}
	if got, _, _ := named.profileAgent(corp, nil); got != corp {
		t.Errorf("an assignment naming the current identity lost to the legacy one: %q", got)
	}
}

// 1.0.3 wrote a later namesake's name over the legacy record of an earlier
// one of another domain that held the same uid. The legacy assignment selects
// neither account, before and after the ledger shows both.
func TestLegacyAgentAssignmentWithAnOverwrittenRecordSelectsNeitherAccount(t *testing.T) {
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	corp, lab := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example")), agentidentity.AgentID(legacyBridgeInputs("alice@lab.example"))
	// The record names lab: its sighting came last before the upgrade.
	records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@lab.example")}
	legacyBridgeLedger(t, &records)
	set := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
	}}
	if got, unresolved, _ := set.profileAgent(lab, nil); got != lab || unresolved == nil || !unresolved(legacy) {
		t.Fatalf("one overwritten row selected %q without unresolved legacy ownership", got)
	}
	// corp's agent is seen after the upgrade.
	records = append(records, legacyBridgeRecord(corp, "alice@corp.example"))
	if got, _, _ := set.profileAgent(lab, nil); got != lab {
		t.Fatalf("the legacy row selected an account before refresh: %q", got)
	}
	set.agentBridge.readAt = time.Time{}
	if got, _, _ := set.profileAgent(lab, nil); got != lab {
		t.Errorf("lab's agent matches as %q after corp was recorded, want its own identity %q", got, lab)
	}
	if got, _, _ := set.profileAgent(corp, nil); got != corp {
		t.Errorf("corp's agent matches as %q, want its own identity %q", got, corp)
	}
	// Another machine's, or another uid's, namesake proves nothing here.
	other := legacyBridgeRecord(corp, "alice@corp.example")
	other.MachineHash = agentidentity.MachineHash("fedcba9876543210fedcba9876543210")
	records = []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@lab.example"), other}
	fresh := &guardrailProfileSet{assignments: set.assignments}
	if got, _, _ := fresh.profileAgent(lab, nil); got != lab {
		t.Errorf("a namesake on another machine selected the legacy policy: %q", got)
	}
}

// An assignment whose agents entry may be the agent's 1.0.3 identity, while
// the ledger cannot say whose it is, selects the outage default
// (default_lookup_failed) for the hook: a later, weaker assignment does not
// apply in its place. An agent the entry cannot name keeps its own match.
func TestUnresolvedLegacyAgentAssignmentSelectsTheOutageDefault(t *testing.T) {
	stubProfileSources(t)
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	corp, lab := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example")), agentidentity.AgentID(legacyBridgeInputs("alice@lab.example"))
	bob := agentidentity.Inputs{
		MachineHash: agentidentity.MachineHash("0123456789abcdef0123456789abcdef"), UserID: "70002",
		Connector: "codex", InstallFP: "/home/bob/.codex", Account: "bob@corp.example",
	}
	other := agentidentity.AgentID(bob)
	legacyBridgeDerives(t, legacyBridgeInputs("alice@corp.example"), legacyBridgeInputs("alice@lab.example"), bob)
	// 1.0.3 recorded the entry for both namesakes of uid 70001.
	records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@lab.example"), legacyBridgeRecord(corp, "alice@corp.example")}
	legacyBridgeLedger(t, &records)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action"}, "watch": {Mode: "observe"}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Agents: []string{legacy}}},
		{Profile: "watch", Match: config.ProfileMatch{Connectors: []string{"codex"}}},
	}
	cfg.Guardrail.DefaultProfile = "strict"
	hook := func(agent string) (profileDecision, string) {
		api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
		profileAgentSource = func(context.Context) (string, bool) { return agent, true }
		ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "70001", UserName: "alice"})
		ctx = api.withGuardrailProfileDecision(ctx, "codex")
		return api.resolveProfile(ctx), api.agentHookMode(ctx, "codex")
	}
	for name, agent := range map[string]string{"corp": corp, "lab": lab} {
		if got, mode := hook(agent); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
			t.Errorf("%s: profile %+v, mode %q; want the outage default strict (action)", name, got, mode)
		}
	}
	if got, mode := hook(other); got.Name != "watch" || got.Match != profileMatchConnector || mode != "observe" {
		t.Errorf("another account's agent: profile %+v, mode %q; want its connector assignment", got, mode)
	}
	// The ledger cannot be read: the entry may be the agent's own legacy
	// identity, and any agent's when the request does not derive that.
	profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) { return nil, false }
	if got, mode := hook(corp); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
		t.Errorf("unreadable ledger, corp: profile %+v, mode %q; want the outage default strict (action)", got, mode)
	}
	if got, mode := hook(other); got.Name != "watch" || got.Match != profileMatchConnector || mode != "observe" {
		t.Errorf("unreadable ledger, another account: profile %+v, mode %q; want its connector assignment", got, mode)
	}
	legacyBridgeDerives(t)
	if got, mode := hook(other); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
		t.Errorf("unreadable ledger, not derived: profile %+v, mode %q; want the outage default strict (action)", got, mode)
	}
	// A current-ID assignment later in the list cannot skip an earlier
	// legacy entry whose owner is unproven: the hook path derives that entry
	// for corp's agent with its request.
	legacyBridgeDerives(t, legacyBridgeInputs("alice@corp.example"))
	cfg.Guardrail.ProfileAssignments = append(slices.Clone(cfg.Guardrail.ProfileAssignments),
		config.ProfileAssignment{Profile: "watch", Match: config.ProfileMatch{Agents: []string{corp}}})
	if got, mode := hook(corp); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
		t.Errorf("later current identity bypassed the unresolved legacy entry: %+v, mode %q", got, mode)
	}
	// An assignment naming the agent's current identity, listed first, does
	// not skip the unresolved legacy entry either: the strictest of them
	// wins whatever their order. Rebinding removes the legacy entry.
	cfg.Guardrail.ProfileAssignments = append([]config.ProfileAssignment{
		{Profile: "watch", Match: config.ProfileMatch{Agents: []string{corp}}},
	}, cfg.Guardrail.ProfileAssignments...)
	if got, _ := hook(corp); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed {
		t.Errorf("named identity before a legacy entry: profile %+v, want strict", got)
	}
}

// legacyBridgeHook resolves the profile and hook mode of a request of agent
// by alice (uid 70001) for codex under assignments: the 1.0.3 entry first
// (relaxed), then every codex agent (watch); the default is strict.
func legacyBridgeHook(t *testing.T, legacy string) func(agent string) (profileDecision, string) {
	t.Helper()
	stubProfileSources(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict": {Mode: "action"}, "relaxed": {Mode: "action"}, "watch": {Mode: "observe"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
		{Profile: "watch", Match: config.ProfileMatch{Connectors: []string{"codex"}}},
	}
	cfg.Guardrail.DefaultProfile = "strict"
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	return func(agent string) (profileDecision, string) {
		profileAgentSource = func(context.Context) (string, bool) { return agent, true }
		ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "70001", UserName: "alice"})
		ctx = api.withGuardrailProfileDecision(ctx, "codex")
		return api.resolveProfile(ctx), api.agentHookMode(ctx, "codex")
	}
}

// A pruned 1.0.3 row cannot supply independent proof of an assignment's
// owner; the account stays on its outage fallback until rebind.
func TestPrunedLegacyAgentAssignmentNeedsRebind(t *testing.T) {
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	corp, lab := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example")), agentidentity.AgentID(legacyBridgeInputs("alice@lab.example"))
	old, now := time.Now().Add(-200*24*time.Hour), time.Now()
	at := func(rec inventory.AgentIdentityRecord, seen time.Time) inventory.AgentIdentityRecord {
		rec.FirstSeen, rec.LastSeen = seen, seen
		return rec
	}
	pruned := func(t *testing.T, records ...inventory.AgentIdentityRecord) {
		t.Helper()
		st, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := st.UpsertAgentIdentities(t.Context(), records); err != nil {
			t.Fatal(err)
		}
		if _, err := st.PruneAgentIdentities(t.Context(), now.Add(-90*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		previous := profileAgentLedger
		t.Cleanup(func() { profileAgentLedger = previous })
		profileAgentLedger = func(filter inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) {
			records, _, err := st.ListAgentIdentities(context.Background(), filter)
			return records, err == nil
		}
	}
	outage := func(t *testing.T, what string, got profileDecision, mode string) {
		t.Helper()
		if got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
			t.Errorf("%s: profile %+v, mode %q; want the outage default strict (action)", what, got, mode)
		}
	}
	t.Run("pruned legacy record", func(t *testing.T) {
		pruned(t, at(legacyBridgeRecord(legacy, "alice@corp.example"), old), at(legacyBridgeRecord(corp, "alice@corp.example"), now))
		hook := legacyBridgeHook(t, legacy)
		got, mode := hook(corp)
		outage(t, "corp's agent after the prune", got, mode)
	})
	t.Run("pruned namesake", func(t *testing.T) {
		pruned(t, at(legacyBridgeRecord(legacy, "alice@lab.example"), old), at(legacyBridgeRecord(corp, "alice@corp.example"), old))
		hook := legacyBridgeHook(t, legacy)
		got, mode := hook(lab)
		outage(t, "lab's agent after the namesake's record was pruned", got, mode)
	})
	t.Run("pruned before the upgrade", func(t *testing.T) {
		// 1.0.3 pruned its own record of the idle agent: only the record
		// 1.0.4 wrote is left.
		pruned(t, at(legacyBridgeRecord(corp, "alice@corp.example"), now))
		hook := legacyBridgeHook(t, legacy)
		got, mode := hook(corp)
		outage(t, "corp's agent without a 1.0.3 record", got, mode)
	})
	t.Run("not recorded yet", func(t *testing.T) {
		pruned(t)
		bobIn := agentidentity.Inputs{
			MachineHash: agentidentity.MachineHash("0123456789abcdef0123456789abcdef"), UserID: "70002",
			Connector: "codex", InstallFP: "/home/bob/.codex", Account: "bob@corp.example",
		}
		legacyBridgeDerives(t, legacyBridgeInputs("alice@corp.example"), bobIn)
		hook := legacyBridgeHook(t, legacy)
		got, mode := hook(corp)
		outage(t, "corp's agent the hook path derived", got, mode)
		bob := agentidentity.AgentID(bobIn)
		if got, mode := hook(bob); got.Name != "watch" || got.Match != profileMatchConnector || mode != "observe" {
			t.Errorf("another account's agent: profile %+v, mode %q; want its connector assignment", got, mode)
		}
	})
}

// An agent ledger that cannot be read does not make every agents entry a
// possible legacy identity once the hook path derived the agent's own.
// Another account's current identity listed first leaves this account's
// exact current-identity assignment in force, as it was before the upgrade
// bridge, instead of sending it to a weaker default_lookup_failed. Only the
// legacy identity derived for this agent is a real conflict; then, and when
// nothing is derived, the request gets the strictest profile that may
// apply, never a weaker one.
func TestUnreadableLedgerKeepsExactCurrentAgentAssignment(t *testing.T) {
	stubProfileSources(t)
	previousLedger := profileAgentLedger
	t.Cleanup(func() { profileAgentLedger = previousLedger })
	profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) { return nil, false }
	legacyBridgeDerives(t)
	aliceInputs := legacyBridgeInputs("alice@corp.example")
	alice, legacy := agentidentity.AgentID(aliceInputs), agentidentity.LegacyAgentID(aliceInputs)
	bob := agentidentity.AgentID(agentidentity.Inputs{
		MachineHash: aliceInputs.MachineHash, UserID: "70002",
		Connector: "codex", InstallFP: "/home/bob/.codex", Account: "bob@corp.example",
	})
	if legacy == "" || alice == bob || alice == legacy {
		t.Fatalf("alice %q, legacy %q, bob %q: want three identities", alice, legacy, bob)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action"}, "watch": {Mode: "observe"}}
	cfg.Guardrail.DefaultProfile = "watch"
	hook := func(agent string) (profileDecision, string) {
		api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
		profileAgentSource = func(context.Context) (string, bool) { return agent, true }
		ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "70001", UserName: "alice"})
		ctx = api.withGuardrailProfileDecision(ctx, "codex")
		return api.resolveProfile(ctx), api.agentHookMode(ctx, "codex")
	}
	want := func(what string, got profileDecision, mode, name, match, wantMode string) {
		t.Helper()
		if got.Name != name || got.Match != match || mode != wantMode {
			t.Errorf("%s: profile %+v, mode %q; want %s (%s, %s)", what, got, mode, name, match, wantMode)
		}
	}

	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "watch", Match: config.ProfileMatch{Agents: []string{bob}}},
		{Profile: "strict", Match: config.ProfileMatch{Agents: []string{alice}}},
	}
	// Nothing derived: bob's entry may be alice's legacy identity, so the
	// request gets the strictest profile that may apply, never weaker than
	// its exact assignment.
	got, mode := hook(alice)
	// The exact assignment is the strictest that may apply, so it keeps
	// its own reason (r104 identity).
	want("exact current identity, nothing derived", got, mode, "strict", profileMatchAgent, "action")
	legacyBridgeDerives(t, aliceInputs)
	got, mode = hook(alice)
	want("exact current identity, legacy derived but not assigned", got, mode, "strict", profileMatchAgent, "action")

	// Another agent's identity is no conflict for a later connector
	// assignment either, once the hook path derived this agent's legacy one.
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "watch", Match: config.ProfileMatch{Agents: []string{bob}}},
		{Profile: "strict", Match: config.ProfileMatch{Connectors: []string{"codex"}}},
	}
	got, mode = hook(alice)
	want("connector assignment after another agent's entry", got, mode, "strict", profileMatchConnector, "action")

	// The legacy identity derived for this agent, listed first, is a real
	// conflict: the exact assignment after it does not skip it, and the
	// request gets the strictest profile that may apply, never the entry's
	// weaker one or the default.
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "watch", Match: config.ProfileMatch{Agents: []string{bob}}},
		{Profile: "watch", Match: config.ProfileMatch{Agents: []string{legacy}}},
		{Profile: "strict", Match: config.ProfileMatch{Agents: []string{alice}}},
	}
	got, mode = hook(alice)
	want("exact identity after its own legacy entry", got, mode, "strict", profileMatchAgent, "action")
}
