// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package agentidentity

import (
	"regexp"
	"testing"
)

// Two directory principals of one short name in two domains that hold one
// uid in turn get two agent identities, and the second is a reassignment
// of the first's uid. Both account forms name their 1.0.3 ID as legacy.
func TestQualifiedAccountsOfTwoDomainsGetTwoIdentities(t *testing.T) {
	machine := MachineHash("0123456789abcdef0123456789abcdef")
	in := func(account string) Inputs {
		return Inputs{MachineHash: machine, UserID: "70001", Connector: "codex", InstallFP: "/home/alice/.codex", Account: account}
	}
	corp, lab := AgentID(in("alice@corp.example")), AgentID(in("alice@lab.example"))
	if corp == "" || corp == lab {
		t.Fatalf("AgentID corp %q, lab %q; want two identities", corp, lab)
	}
	if AgentID(in("ALICE@Corp.Example")) != corp {
		t.Errorf("the case of a qualified name changed its ID")
	}
	if !UIDReassigned("70001", "alice@corp.example", "alice@lab.example") {
		t.Errorf("a namesake from another domain is not a reassignment of the uid")
	}
	if UIDReassigned("70001", "alice@corp.example", "alice") || UIDReassigned("70001", "alice", "CORP\\alice") {
		t.Errorf("a bare name proves no other domain")
	}
	bare := AgentID(in("alice"))
	legacy := LegacyAgentID(in("alice@corp.example"))
	if legacy == bare || LegacyAgentID(in("alice@lab.example")) != legacy {
		t.Errorf("LegacyAgentID = %q, want one domain-free ID distinct from bare %q", legacy, bare)
	}
	if LegacyAgentID(in("alice")) != legacy {
		t.Errorf("a bare account's legacy ID differs from the old domain-free ID")
	}
	if got := AgentID(in("alice")); got != "agt-"+digest16(agentNamespace, machine, "70001", "codex", "/home/alice/.codex", "alice", "account-kind:bare", "account-namespace:1.0.4") {
		t.Errorf("a bare account's ID changed: %q", got)
	}
}

// A 1.0.3 assignment for a qualified account names the domain-free ID.
// A replacement bare account with the same uid and install path must never
// receive that ID, even on a cold upgrade with no agent sightings yet.
func TestBareReplacementDoesNotReuseQualifiedLegacyID(t *testing.T) {
	base := Inputs{MachineHash: MachineHash("0123456789abcdef0123456789abcdef"), UserID: "70001",
		Connector: "codex", InstallFP: "/home/alice/.codex", Account: "CORP\\alice"}
	legacy := LegacyAgentID(base)
	base.Account = "alice"
	if got := AgentID(base); got == legacy {
		t.Fatalf("bare replacement inherited qualified legacy ID %q", got)
	}
	if got := LegacyAgentID(base); got != legacy {
		t.Fatalf("bare account legacy ID = %q, want historical %q for guarded migration", got, legacy)
	}
	bare := AgentID(base)
	base.Account = "alice@account-kind:bare"
	if got := AgentID(base); got == bare {
		t.Fatalf("a real directory named like the bare marker collided with %q", bare)
	}
}

func TestDerivationTable(t *testing.T) {
	machine := MachineHash("0123456789abcdef0123456789abcdef")
	base := Inputs{MachineHash: machine, UserID: "1001", Connector: "claudecode", InstallFP: "/home/alice/.claude"}
	baseID := AgentID(base)
	if !regexp.MustCompile(`^agt-[0-9a-f]{16}$`).MatchString(baseID) {
		t.Fatalf("AgentID = %q, want agt- plus 16 hex", baseID)
	}
	with := func(edit func(*Inputs)) Inputs { in := base; edit(&in); return in }
	for _, tc := range []struct {
		name string
		in   Inputs
		same bool
	}{
		{"spacing and connector case", with(func(in *Inputs) { in.UserID, in.Connector = " 1001 ", "ClaudeCode" }), true},
		{"trailing separator", with(func(in *Inputs) { in.InstallFP = "/home/alice/.claude/" }), true},
		{"machine id case", with(func(in *Inputs) { in.MachineHash = MachineHash("0123456789ABCDEF0123456789ABCDEF") }), true},
		{"other machine", with(func(in *Inputs) { in.MachineHash = MachineHash("ffff") }), false},
		{"other user", with(func(in *Inputs) { in.UserID = "1002" }), false},
		{"other connector", with(func(in *Inputs) { in.Connector = "codex" }), false},
		{"other install", with(func(in *Inputs) { in.InstallFP = "/home/alice/.claude-work" }), false},
	} {
		if got := AgentID(tc.in); (got == baseID) != tc.same {
			t.Errorf("%s: AgentID = %q, base %q, want same=%v", tc.name, got, baseID, tc.same)
		}
	}
	for _, in := range []Inputs{
		with(func(in *Inputs) { in.MachineHash = "" }),
		with(func(in *Inputs) { in.UserID = "" }),
		with(func(in *Inputs) { in.Connector = "" }),
	} {
		if got := AgentID(in); got != "" {
			t.Errorf("AgentID(%+v) = %q, want empty for a missing component", in, got)
		}
	}
	sid := Inputs{MachineHash: machine, UserID: "s-1-5-21-1-2-3-1001", Connector: "codex", InstallFP: `C:\Users\Alice\.codex\`}
	sidUpper := Inputs{MachineHash: machine, UserID: "S-1-5-21-1-2-3-1001", Connector: "codex", InstallFP: `c:/users/alice/.codex`}
	if AgentID(sid) != AgentID(sidUpper) {
		t.Errorf("Windows SID and path spellings derived different IDs")
	}

	a, b := InstanceID(baseID, "session-1"), InstanceID(baseID, "session-2")
	if !regexp.MustCompile(`^ais-[0-9a-f]{16}$`).MatchString(a) || a == b {
		t.Fatalf("InstanceID: %q, %q; want distinct ais- ids", a, b)
	}
	if a != InstanceID(baseID, "session-1") || a == InstanceID(AgentID(with(func(in *Inputs) { in.UserID = "1002" })), "session-1") {
		t.Errorf("InstanceID is not keyed by (agent, session)")
	}
	if InstanceID(baseID, "") != "" {
		t.Errorf("InstanceID without a session must be empty")
	}
	sub := SubagentInstanceID(a, "agent-7")
	if sub == "" || sub == a || sub != SubagentInstanceID(a, "agent-7") || sub == SubagentInstanceID(b, "agent-7") {
		t.Errorf("SubagentInstanceID = %q; want stable, distinct from its parent and keyed by parent", sub)
	}
}

// Review loop 2, finding 1: the legacy ID is the one 1.0.0 to 1.0.3
// derived, which named no account incarnation (those builds kept none).
// An incarnation keys the current ID only; before, it changed the legacy
// ID too, so an assignment 1.0.3 wrote for the account matched nothing.
func TestLegacyAgentIDIgnoresTheAccountIncarnation(t *testing.T) {
	machine := MachineHash("0123456789abcdef0123456789abcdef")
	for _, account := range []string{"alice", "alice@corp.example", `CORP\alice`} {
		in := Inputs{MachineHash: machine, UserID: "70001", Connector: "codex", InstallFP: "/home/alice/.codex", Account: account}
		// The derivation of 1.0.0 to 1.0.3.
		want := AgentIDPrefix + digest16(agentNamespace, machine, "70001", "codex", "/home/alice/.codex", "alice")
		if got := LegacyAgentID(in); got != want {
			t.Errorf("%s: legacy %q; want the 1.0.3 ID %q", account, got, want)
		}
		tagged := in
		tagged.Incarnation = "record:5F1C0A1E-0000-4000-8000-000000000001"
		if got := LegacyAgentID(tagged); got != want {
			t.Errorf("%s with an incarnation: legacy %q; want the 1.0.3 ID %q", account, got, want)
		}
		if AgentID(tagged) == AgentID(in) || AgentID(tagged) == want {
			t.Errorf("%s: the incarnation does not key the current ID", account)
		}
	}
	sid := Inputs{MachineHash: machine, UserID: "S-1-5-21-1-2-3-1001", Connector: "codex", InstallFP: "c:/users/alice/.codex", Incarnation: "x"}
	if got := LegacyAgentID(sid); got != "" {
		t.Errorf("SID: legacy %q; want none", got)
	}
}
