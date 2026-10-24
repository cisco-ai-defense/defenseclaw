// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// strictBridge resolves hook requests of codex agents the way the hook path
// derives their identities: uid 70001 is account, every other uid is
// u<uid>@corp.example.
type strictBridge struct {
	t       *testing.T
	account string
	homes   map[int]string
}

func newStrictBridge(t *testing.T, account string) *strictBridge {
	t.Helper()
	agentIdentityTestSetup(t)
	stubProfileSources(t)
	profileAgentSource = requestAgentIdentity
	restoreAccount := agentIdentityAccountName
	t.Cleanup(func() { agentIdentityAccountName = restoreAccount })
	b := &strictBridge{t: t, account: account, homes: map[int]string{}}
	agentIdentityAccountName = func(id string) string {
		if id == "70001" {
			return b.account
		}
		return "u" + id + "@corp.example"
	}
	return b
}

// peer is the hook context of uid's agent.
func (b *strictBridge) peer(uid int) context.Context {
	home, ok := b.homes[uid]
	if !ok {
		home = b.t.TempDir()
		b.homes[uid] = home
	}
	return withManagedHookPeer(b.t.Context(), managedHookPeer{UID: uid, Name: agentIdentityAccountName(strconv.Itoa(uid)), Home: home})
}

// inputs are the identity inputs of uid's agent as account.
func (b *strictBridge) inputs(uid int, account string) agentidentity.Inputs {
	facts := resolveHookAgentIdentity(b.peer(uid), agentHookRequest{ConnectorName: "codex"})
	if facts.ID == "" {
		b.t.Fatal("the hook path derived no agent identity")
	}
	return agentidentity.Inputs{
		MachineHash: facts.MachineHash, UserID: facts.UserID, Account: account,
		Connector: facts.Connector, InstallFP: facts.InstallFP,
	}
}

// record is the ledger's record of uid's agent under id, named account.
func (b *strictBridge) record(uid int, id, account string) inventory.AgentIdentityRecord {
	in := b.inputs(uid, account)
	return inventory.AgentIdentityRecord{
		AgentID: id, UserID: in.UserID, UserName: account, Connector: in.Connector,
		InstallFP: in.InstallFP, MachineHash: in.MachineHash,
	}
}

// ledger serves records; nil records is a ledger that cannot be read.
func (b *strictBridge) ledger(records []inventory.AgentIdentityRecord) {
	previous := profileAgentLedger
	b.t.Cleanup(func() { profileAgentLedger = previous })
	profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) {
		return slices.Clone(records), records != nil
	}
}

// hook resolves the profile and hook mode of a codex hook request of uid's
// agent under cfg.
func (b *strictBridge) hook(cfg *config.Config, uid int, subject profileSubject) (profileDecision, string) {
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	ctx := context.WithValue(b.peer(uid), testVerifiedSubjectKey{}, subject)
	ctx = api.withGuardrailProfileDecision(ctx, "codex")
	return api.resolveProfile(ctx), api.agentHookMode(ctx, "codex")
}

// strictBridgeConfig assigns first the profile legacyProfile to the agents
// entry legacy, then laterProfile to every codex agent; the default is
// defaultProfile.
func strictBridgeConfig(profiles map[string]config.GuardrailProfile, legacy, legacyProfile, laterProfile, defaultProfile string) *config.Config {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = profiles
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: legacyProfile, Match: config.ProfileMatch{Agents: []string{legacy}}},
		{Profile: laterProfile, Match: config.ProfileMatch{Connectors: []string{"codex"}}},
	}
	cfg.Guardrail.DefaultProfile = defaultProfile
	return cfg
}

var strictBridgeModes = map[string]config.GuardrailProfile{"strict": {Mode: "action"}, "watch": {Mode: "observe"}}

// An agents entry that may be the agent's 1.0.3 identity, while the ledger
// cannot prove whose it is, never resolves the agent to a weaker profile
// than one that may apply: not to a permissive default_profile, and not to
// a later assignment. The request gets the strictest of the default, the
// entry's profile and the profile it would match otherwise.
func TestUnresolvedLegacyAgentAssignmentIsNeverWeakerThanItsProfile(t *testing.T) {
	alice := profileSubject{UserID: "70001", UserName: "alice"}
	want := func(t *testing.T, what string, got profileDecision, mode, profile, wantMode string) {
		t.Helper()
		if got.Name != profile || got.Match != profileMatchDefaultLookupFailed || mode != wantMode {
			t.Errorf("%s: profile %+v, mode %q; want %s (%s) as default_lookup_failed", what, got, mode, profile, wantMode)
		}
	}
	setup := func(t *testing.T) (*strictBridge, string, string) {
		b := newStrictBridge(t, "alice@corp.example")
		in := b.inputs(70001, "alice@corp.example")
		return b, agentidentity.LegacyAgentID(in), agentidentity.AgentID(in)
	}
	t.Run("ledger cannot be read", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger(nil)
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "strict", "watch", "watch"), 70001, alice)
		want(t, "cold ledger", got, mode, "strict", "action")
	})
	t.Run("ledger cannot be read and the directory lookup failed", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger(nil)
		failed := alice
		failed.LookupFailed = true
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "strict", "watch", "watch"), 70001, failed)
		want(t, "cold ledger, failed lookup", got, mode, "strict", "action")
	})
	t.Run("namesakes of two domains", func(t *testing.T) {
		b, legacy, corp := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{
			b.record(70001, legacy, "alice@lab.example"), b.record(70001, corp, "alice@corp.example"),
		})
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "strict", "watch", "watch"), 70001, alice)
		want(t, "ambiguous entry", got, mode, "strict", "action")
	})
	t.Run("1.0.3 record pruned before the upgrade", func(t *testing.T) {
		b, legacy, corp := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{b.record(70001, corp, "alice@corp.example")})
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "strict", "watch", "watch"), 70001, alice)
		want(t, "no 1.0.3 record", got, mode, "strict", "action")
	})
	t.Run("a lower block_at blocks more", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger(nil)
		profiles := map[string]config.GuardrailProfile{
			"tight": {Mode: "action", BlockAt: "low"}, "alert": {Mode: "action", BlockAt: "critical"},
		}
		got, mode := b.hook(strictBridgeConfig(profiles, legacy, "tight", "alert", "alert"), 70001, alice)
		want(t, "block_at", got, mode, "tight", "action")
	})
	t.Run("a later assignment enforces more", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger(nil)
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "watch", "strict", "watch"), 70001, alice)
		// The later connector assignment is the strictest and keeps its
		// own reason (r104 identity).
		if got.Name != "strict" || mode != "action" || got.Match != profileMatchConnector {
			t.Errorf("later assignment: profile %+v, mode %q; want strict (action) as connector", got, mode)
		}
	})
	t.Run("the default enforces more", func(t *testing.T) {
		// The proven connector assignment gives watch whether or not the
		// entry is the agent's, so the default never applies and nothing
		// is refused: the decision needs no unproven fact.
		b, legacy, _ := setup(t)
		b.ledger(nil)
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "watch", "watch", "strict"), 70001, alice)
		if got.Name != "watch" || mode != "observe" || got.Match != profileMatchConnector || got.Refused != "" {
			t.Errorf("strict default: profile %+v, mode %q; want watch (observe) as connector, not refused", got, mode)
		}
	})
	t.Run("another account's agent", func(t *testing.T) {
		// Its own 1.0.3 identity is derived with its request: the entry
		// cannot be it, even before the ledger answers.
		b, legacy, _ := setup(t)
		b.ledger(nil)
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "strict", "watch", "strict"), 70002,
			profileSubject{UserID: "70002", UserName: "u70002"})
		if got.Name != "watch" || got.Match != profileMatchConnector || mode != "observe" {
			t.Errorf("another account's agent: profile %+v, mode %q; want its connector assignment", got, mode)
		}
	})
}

// An account whose spelling changed after the upgrade (alice or CORP\alice
// in 1.0.3, alice@corp.example now) derives an identity no 1.0.3 record is
// linked to, and nothing proves the spellings are one account: its 1.0.3
// entry stays closed, the strictest profile that may apply, never a
// permissive default.
func TestLegacyAgentAssignmentAcrossAnAccountSpellingIsNeverWeaker(t *testing.T) {
	alice := profileSubject{UserID: "70001", UserName: "alice"}
	for _, spelled := range []string{"alice", `CORP\alice`, "ALICE@corp.example"} {
		t.Run(spelled, func(t *testing.T) {
			b := newStrictBridge(t, "alice@corp.example")
			now := b.inputs(70001, "alice@corp.example")
			legacy, corp := agentidentity.LegacyAgentID(now), agentidentity.AgentID(now)
			// 1.0.3 gave every spelling the legacy identity.
			if old := agentidentity.LegacyAgentID(b.inputs(70001, "alice")); old != legacy {
				t.Fatalf("1.0.3 identity %q, want the legacy identity %q", old, legacy)
			}
			for _, records := range [][]inventory.AgentIdentityRecord{
				{b.record(70001, legacy, spelled)},
				{b.record(70001, legacy, spelled), b.record(70001, corp, "alice@corp.example")},
			} {
				b.ledger(records)
				got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "strict", "watch", "watch"), 70001, alice)
				// Nothing proves the account incarnation here (no token
				// was ever known), so not even the same domain's record
				// proves the account (GAP-0337).
				if got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
					t.Errorf("%d records: profile %+v, mode %q; want strict (action) as default_lookup_failed", len(records), got, mode)
				}
			}
		})
	}
	// The other way round, the host names the account without its domain
	// now: a bare account has its own namespace since 1.0.4 (GAP-0424), so
	// the 1.0.3 entry is not proven to be its own either.
	t.Run("qualified before, bare now", func(t *testing.T) {
		b := newStrictBridge(t, "alice")
		legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice@corp.example"))
		b.ledger([]inventory.AgentIdentityRecord{b.record(70001, legacy, "alice@corp.example")})
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "strict", "watch", "watch"), 70001, alice)
		if got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
			t.Errorf("profile %+v, mode %q; want strict as default_lookup_failed", got, mode)
		}
	})
}

// The 1.0.3 identity of a request's agent is derived with the request, so
// no number of identities derived before it can drop it: an agent the
// ledger has not recorded yet still gets the strictest profile its 1.0.3
// entry may apply.
func TestLegacyAgentIdentityIsDerivedForEveryRequest(t *testing.T) {
	b := newStrictBridge(t, "alice@corp.example")
	for uid := 80000; uid < 80000+5000; uid++ {
		ctx := withManagedHookPeer(t.Context(), managedHookPeer{UID: uid, Name: fmt.Sprintf("u%d@corp.example", uid), Home: "/home/u"})
		if resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"}).ID == "" {
			t.Fatal("the hook path derived no agent identity")
		}
	}
	legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice@corp.example"))
	b.ledger([]inventory.AgentIdentityRecord{})
	got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "strict", "watch", "watch"), 70001, profileSubject{UserID: "70001", UserName: "alice"})
	if got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
		t.Errorf("after 5000 other identities: profile %+v, mode %q; want strict (action) as default_lookup_failed", got, mode)
	}
}

// Explain names an agent by its identity only. The ledger's record of the
// identity says what its 1.0.3 identity is; an identity the ledger has not
// recorded is unproven and gets the strictest profile that may apply.
func TestExplainOfAnUnrecordedAgentIsNeverWeaker(t *testing.T) {
	b := newStrictBridge(t, "alice@corp.example")
	corpIn := b.inputs(70001, "alice@corp.example")
	legacy, corp := agentidentity.LegacyAgentID(corpIn), agentidentity.AgentID(corpIn)
	bobIn := b.inputs(70002, "bob")
	bob := agentidentity.AgentID(bobIn)
	cfg := strictBridgeConfig(strictBridgeModes, legacy, "strict", "watch", "watch")
	explain := func(agent, uid string) profileDecision {
		set := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg).guardrailProfileSet()
		return set.matchAgent(&profileSubject{UserID: uid, UserName: "x"}, profileSubjectLookup, "codex", nil, agent, nil)
	}
	b.ledger([]inventory.AgentIdentityRecord{})
	if got := explain(corp, "70001"); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed {
		t.Errorf("unrecorded agent: %+v; want strict as default_lookup_failed", got)
	}
	b.ledger([]inventory.AgentIdentityRecord{b.record(70001, corp, "alice@corp.example"), b.record(70002, bob, "bob")})
	if got := explain(corp, "70001"); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed {
		t.Errorf("recorded agent without its 1.0.3 record: %+v; want strict as default_lookup_failed", got)
	}
	if got := explain(bob, "70002"); got.Name != "watch" || got.Match != profileMatchConnector {
		t.Errorf("recorded agent of an account without a domain: %+v; want its connector assignment", got)
	}
}
