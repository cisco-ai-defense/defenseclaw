// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// Review of GAP-0947 (loop 2): CORP's alice and OTHER's alice hold one uid
// in turn, with one bare name and home, and run the same connector on the
// same machine. Each derives its own agent identity, so OTHER's alice does
// not get the match.agents profile of CORP's agent nor its ledger row
// (first_seen, sessions); CORP's alice keeps the ID it had before the
// incarnation was known, and gets it back when it holds the uid again. The
// tokens survive a restart, and an outage keeps the last one.
func TestAgentIdentityFollowsTheAccountIncarnationAcrossUIDReuse(t *testing.T) {
	agentIdentityTestSetup(t)
	const uid = 41401
	id := strconv.Itoa(uid)
	const corp, other = "sid:S-1-5-21-1-1-1-1401", "sid:S-1-5-21-2-2-2-1401"
	home, store := t.TempDir(), filepath.Join(t.TempDir(), "peer-homes.json")
	previousHomes, previousFacts := managedHookPeerHomes, identityFactsEnabled.Load()
	previousIncarnation, previousName := managedHookPeerAccountIncarnation, userScopedIdentityName
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccountIncarnation, userScopedIdentityName = previousHomes, previousIncarnation, previousName
		setIdentityFactsEnabled(previousFacts)
	})
	setIdentityFactsEnabled(true)
	userScopedIdentityName = func(got string) string {
		if got == id {
			return "alice"
		}
		return ""
	}
	var mu sync.Mutex
	incarnation, known := corp, true
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		return incarnation, known
	}
	now := time.Unix(3_000_000, 0)
	start := func() {
		managedHookPeerHomes = &managedHookPeerHomeCache{
			newResolver: func() unixidentity.Resolver {
				return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{uid: {Name: "alice", UID: uid, Home: home}}}
			},
			now: func() time.Time { return now },
		}
		managedHookPeerHomes.setStore(store)
	}
	holds := func(token string, ok bool) {
		mu.Lock()
		incarnation, known = token, ok
		mu.Unlock()
		now = now.Add(managedHookPeerHomeTTL + time.Second)
	}
	hook := func() agentIdentityFacts {
		t.Helper()
		peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, Name: "alice", Home: home})
		facts := resolveHookAgentIdentity(peer, agentHookRequest{ConnectorName: "codex"})
		if facts.ID == "" {
			t.Fatal("no agent identity")
		}
		return facts
	}

	start()
	corpAgent := hook()
	if before := agentidentity.AgentID(agentidentity.Inputs{MachineHash: corpAgent.MachineHash, UserID: id, Account: "alice",
		Connector: "codex", InstallFP: corpAgent.InstallFP}); corpAgent.ID != before {
		t.Fatalf("the first account's agent identity = %s, want the ID it had before (%s)", corpAgent.ID, before)
	}
	holds(other, true)
	otherAgent := hook()
	if otherAgent.ID == corpAgent.ID {
		t.Fatalf("OTHER's alice derived CORP's agent identity %s", corpAgent.ID)
	}
	holds("", false)
	if got := hook().ID; got != otherAgent.ID {
		t.Fatalf("during an outage the agent identity moved to %s, want %s", got, otherAgent.ID)
	}
	start()
	if got := hook().ID; got != otherAgent.ID {
		t.Fatalf("after a restart during the outage the agent identity is %s, want %s", got, otherAgent.ID)
	}
	holds(corp, true)
	if got := hook().ID; got != corpAgent.ID {
		t.Fatalf("CORP's alice holding the uid again derived %s, want its own %s", got, corpAgent.ID)
	}

	// The ledger keeps each account's row under its own identity.
	st, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	sighting := func(facts agentIdentityFacts, domain, session string, at time.Time) inventory.AgentIdentityRecord {
		return inventory.AgentIdentityRecord{AgentID: facts.ID, UserID: id, UserName: "alice", UserDomain: domain,
			Connector: facts.Connector, InstallFP: facts.InstallFP, MachineHash: facts.MachineHash,
			FirstSeen: at, LastSeen: at, SessionsSeen: 1, SessionIDs: []string{session}, LastSessionID: session}
	}
	ctx := context.Background()
	if err := st.UpsertAgentIdentities(ctx, []inventory.AgentIdentityRecord{sighting(corpAgent, "corp.example", "s-corp", t0)}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentIdentities(ctx, []inventory.AgentIdentityRecord{sighting(otherAgent, "other.example", "s-other", t0.Add(time.Hour))}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.ListAgentIdentities(ctx, inventory.AgentIdentityFilter{})
	if err != nil || len(rows) != 2 {
		t.Fatalf("ledger rows = %+v, %v; want one per account", rows, err)
	}
	for _, row := range rows {
		want := map[string]time.Time{corpAgent.ID: t0, otherAgent.ID: t0.Add(time.Hour)}[row.AgentID]
		if !row.FirstSeen.Equal(want) || row.SessionsSeen != 1 {
			t.Fatalf("row %s first seen %s with %d sessions; want %s and its own session", row.AgentID, row.FirstSeen, row.SessionsSeen, want)
		}
	}

	// While OTHER's alice holds the uid, the listing retires CORP's row.
	holds(other, true)
	hook()
	listed := []agentIdentityRow{{AgentIdentityRecord: rows[0]}, {AgentIdentityRecord: rows[1]}}
	nameAgentIdentityRows(listed)
	for _, row := range listed {
		if row.Retired != (row.AgentID == corpAgent.ID) {
			t.Fatalf("row %s retired %v; want only CORP's agent identity retired", row.AgentID, row.Retired)
		}
	}
}
